"""
Corresponds to: heritage.hh / heritage.cc

Utilities for building Static Single Assignment (SSA) form.
Core classes: LocationMap, MemRange, TaskList, PriorityQueue, HeritageInfo, LoadGuard, Heritage.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Optional, List, Dict, Tuple
from collections import defaultdict
from bisect import bisect_left, bisect_right

from ghidra.core.address import Address, RangeList
from ghidra.core.error import LowlevelError
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_SPACEBASE, IPTR_INTERNAL, IPTR_PROCESSOR, IPTR_IOP
from ghidra.core.opcodes import OpCode
from ghidra.analysis.rangeutil import ValueSetSolver, WidenerFull, WidenerNone

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import FlowBlock, BlockBasic, BlockGraph
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.fspec.fspec import FuncCallSpecs


_HERITAGE_DEBUG = os.environ.get("PYGHIDRA_DEBUG_HERITAGE_ORDER", "")
_HERITAGE_DEBUG_RANGE = os.environ.get("PYGHIDRA_DEBUG_HERITAGE_RANGE", "")


def _heritage_debug_enabled() -> bool:
    return bool(_HERITAGE_DEBUG)


def _debug_heritage(msg: str) -> None:
    if _HERITAGE_DEBUG:
        print(msg, file=sys.stderr)


def _format_range_debug(addr: Address, size: int) -> str:
    space = addr.getSpace()
    space_name = space.getName() if space is not None else "none"
    return f"{space_name}[{addr.getOffset():#x}:{size}]"


def _heritage_debug_range_matches(addr: Address, size: int) -> bool:
    if not _HERITAGE_DEBUG:
        return False
    if not _HERITAGE_DEBUG_RANGE:
        return True
    return _HERITAGE_DEBUG_RANGE in _format_range_debug(addr, size)


def _format_vn_debug(vn: "Varnode") -> str:
    space = vn.getSpace()
    space_name = space.getName() if space is not None else "none"
    state = "written" if vn.isWritten() else ("input" if vn.isInput() else "free")
    return f"{space_name}[{vn.getOffset():#x}:{vn.getSize()}:{state}]"


def _format_vn_list_debug(vns: list["Varnode"]) -> str:
    return "[" + ", ".join(_format_vn_debug(vn) for vn in vns) + "]"


def _sort_space_key(space: Optional[AddrSpace]) -> int:
    """Mirror C++ Address ordering by using address-space index."""
    if space is None:
        return -1
    return space.getIndex()


def _sort_address_key(addr: Address) -> tuple[int, int]:
    """Build a stable Address sort key matching ``Address::__lt__`` semantics."""
    return (_sort_space_key(addr.getSpace()), addr.getOffset())


def _sort_varnode_loc_def_key(vn: "Varnode") -> tuple[int, ...]:
    """Build the C++ ``VarnodeCompareLocDef`` ordering as a Python sort key."""
    input_or_written = vn.getFlags() & 0x18  # Varnode.input | Varnode.written
    key = [
        *_sort_address_key(vn.getAddr()),
        vn.getSize(),
        ((input_or_written - 1) & 0xFFFFFFFF),
    ]
    if input_or_written == 0x10:  # Varnode.written
        seq = vn.getDef().getSeqNum()
        key.extend((*_sort_address_key(seq.getAddr()), seq.getTime()))
    elif input_or_written == 0:
        key.append(vn.getCreateIndex())
    else:
        key.append(0)
    return tuple(key)


def _heritage_space_sort_key(space: Optional[AddrSpace]) -> tuple[int, int]:
    """Approximate the native heritage space iteration order.

    Native x64 traces show ``unique`` ranges being heritaged before
    ``register`` ranges.  Our Python lifter currently assigns the register
    space a lower index than unique, so raw ``arch.getSpace(i)`` iteration
    produces the wrong disjoint/task chronology.  Keep the adjustment local
    to heritage iteration, preferring internal temporaries before processor
    and stack-backed spaces.
    """
    if space is None:
        return (99, 99)
    spc_type = space.getType()
    if spc_type == IPTR_INTERNAL:
        bucket = 0
    elif spc_type == IPTR_PROCESSOR:
        bucket = 1
    elif spc_type == IPTR_SPACEBASE:
        bucket = 2
    else:
        bucket = 3
    return (bucket, space.getIndex())


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
        def __init__(self, size: int, pass_: int):
            self.size = size
            self.pass_ = pass_

    def __init__(self) -> None:
        self._map: Dict[Address, LocationMap.SizePass] = {}
        self._by_base: dict = {}  # base → {addr: SizePass} for fast same-space lookup

    def add(self, addr: Address, size: int, pass_: int,
            intersect_ref: list) -> tuple[Address, "LocationMap.SizePass"]:
        """Mark new address as heritaged and return the containing entry.

        intersect_ref[0] is set to:
          0 if only intersection is with range from the same pass
          1 if there is a partial intersection with something old
          2 if the range is contained in an old range
        """
        intersect_ref[0] = 0

        addr_base = addr.base
        base_bucket = self._by_base.get(addr_base)
        if base_bucket is None:
            base_bucket = {}
            self._by_base[addr_base] = base_bucket
            sorted_addrs: list[Address] = []
        else:
            sorted_addrs = sorted(base_bucket)

        idx = bisect_left(sorted_addrs, addr)
        if idx != 0:
            idx -= 1
        if idx < len(sorted_addrs):
            start_addr = sorted_addrs[idx]
            start_sp = base_bucket[start_addr]
            if addr.overlap(0, start_addr, start_sp.size) == -1:
                idx += 1

        to_delete: list[Address] = []
        if idx < len(sorted_addrs):
            existing_addr = sorted_addrs[idx]
            sp = base_bucket[existing_addr]
            where = addr.overlap(0, existing_addr, sp.size)
            if where != -1:
                if where + size <= sp.size:
                    intersect_ref[0] = 2 if sp.pass_ < pass_ else 0
                    return existing_addr, sp
                addr = existing_addr
                size = where + size
                if sp.pass_ < pass_:
                    intersect_ref[0] = 1
                    pass_ = sp.pass_
                to_delete.append(existing_addr)
                idx += 1

        while idx < len(sorted_addrs):
            existing_addr = sorted_addrs[idx]
            sp = base_bucket[existing_addr]
            where = existing_addr.overlap(0, addr, size)
            if where == -1:
                break
            if where + sp.size > size:
                size = where + sp.size
            if sp.pass_ < pass_:
                intersect_ref[0] = 1
                pass_ = sp.pass_
            to_delete.append(existing_addr)
            idx += 1

        for existing_addr in to_delete:
            del base_bucket[existing_addr]
            del self._map[existing_addr]

        sp = LocationMap.SizePass(size, pass_)
        self._map[addr] = sp
        base_bucket[addr] = sp
        return addr, sp

    def find(self, addr: Address) -> Optional[tuple[Address, "LocationMap.SizePass"]]:
        """Look up the entry containing *addr* using C++ ``upper_bound`` semantics."""
        base_bucket = self._by_base.get(addr.base)
        if not base_bucket:
            return None
        sorted_addrs = sorted(base_bucket)
        idx = bisect_right(sorted_addrs, addr)
        if idx == 0:
            return None
        key = sorted_addrs[idx - 1]
        sp = base_bucket[key]
        if addr.overlap(0, key, sp.size) == -1:
            return None
        return key, sp


    def findPass(self, addr: Address) -> int:
        """Look up if/how given address was heritaged. Returns pass number or -1."""
        result = self.find(addr)
        if result is None:
            return -1
        return result[1].pass_

    def erase(self, iter_or_addr) -> Optional[tuple[Address, "LocationMap.SizePass"]]:
        addr = iter_or_addr[0] if isinstance(iter_or_addr, tuple) else iter_or_addr
        sorted_addrs = sorted(self._map)
        next_entry: Optional[tuple[Address, "LocationMap.SizePass"]] = None
        if addr in self._map:
            idx = sorted_addrs.index(addr)
            if idx + 1 < len(sorted_addrs):
                next_addr = sorted_addrs[idx + 1]
                next_entry = (next_addr, self._map[next_addr])
            if addr in self._map:
                del self._map[addr]
            bb = self._by_base.get(addr.base)
            if bb is not None and addr in bb:
                del bb[addr]
                if not bb:
                    del self._by_base[addr.base]
        return next_entry

    def clear(self) -> None:
        self._map.clear()
        self._by_base.clear()

    def begin(self):
        return iter(sorted(self._map.items(), key=lambda item: item[0]))

    def end(self):
        return None

    def __iter__(self):
        return self.begin()


# =========================================================================
# MemRange
# =========================================================================

class MemRange:
    """An address range to be processed during heritage."""
    new_addresses = 1
    old_addresses = 2

    def __init__(self, addr: Address, size: int, flags: int):
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
        """Add a range to the end of the list, merging only with the tail."""
        if self._list:
            entry = self._list[-1]
            over = addr.overlap(0, entry.addr, entry.size)
            if over >= 0:
                relsize = size + over
                if relsize > entry.size:
                    entry.size = relsize
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
        return 0

    def end(self):
        return len(self._list)

    def clear(self) -> None:
        self._list.clear()

    def sort(self) -> None:
        """Sort ranges by address to match C++ sorted map iteration order."""
        self._list.sort(key=lambda m: (_sort_address_key(m.addr), m.size))

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
        if self._curdepth == -1 and maxdepth == len(self._queue) - 1:
            return
        self._queue = [[] for _ in range(maxdepth + 1)]
        self._curdepth = -1

    def insert(self, bl: FlowBlock, depth: int) -> None:
        """Insert a block into the queue given its priority."""
        self._queue[depth].append(bl)
        if depth > self._curdepth:
            self._curdepth = depth

    def extract(self) -> Optional[FlowBlock]:
        """Retrieve the highest priority block."""
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
        self.maximumOffset = s.getHighest()
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
        maxAddr = self.spc.getHighest()
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
                maxAddr = self.spc.getHighest()
                self.maximumOffset = maxAddr
                self.analysisState = 1
        maxAddr = self.spc.getHighest()
        if self.minimumOffset > maxAddr:
            self.minimumOffset = maxAddr
        if self.maximumOffset > maxAddr:
            self.maximumOffset = maxAddr

    def isRangeLocked(self) -> bool:
        return self.analysisState == 2

    def isValid(self, opc) -> bool:
        """Return True if the record still describes an active LOAD."""
        return (not self.op.isDead()) and self.op.code() == opc


class StackNode:
    nonconstant_index = 1
    multiequal = 2

    __slots__ = ("vn", "offset", "traversals", "descend", "iter")

    def __init__(self, vn, offset: int, traversals: int) -> None:
        self.vn = vn
        self.offset = offset
        self.traversals = traversals
        self.descend = vn.getDescend()
        self.iter = 0


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

    def getInfo(self, spc: AddrSpace) -> HeritageInfo:
        """Get the heritage status for the given address space."""
        return self._infolist[spc.getIndex()]

    def clearInfoList(self) -> None:
        """Reset heritage status for all address spaces."""
        for info in self._infolist:
            info.reset()

    def buildInfoList(self) -> None:
        """Initialize information for each space."""
        if self._infolist:
            return
        arch = self._fd.getArch()
        for i in range(arch.numSpaces()):
            self._infolist.append(HeritageInfo(arch.getSpace(i)))

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
        if not info.isHeritaged():
            raise LowlevelError("Trying to calculate passes for non-heritaged space")
        return self._pass - info.delay

    def seenDeadCode(self, spc: AddrSpace) -> None:
        """Inform system of dead code removal in given space."""
        info = self.getInfo(spc)
        info.deadremoved = 1

    def getDeadCodeDelay(self, spc: AddrSpace) -> int:
        """Get pass delay for heritaging the given space."""
        info = self.getInfo(spc)
        return info.deadcodedelay

    def setDeadCodeDelay(self, spc: AddrSpace, delay: int) -> None:
        """Set delay for a specific space."""
        info = self.getInfo(spc)
        if delay < info.delay:
            raise LowlevelError("Illegal deadcode delay setting")
        info.deadcodedelay = delay

    def deadRemovalAllowed(self, spc: AddrSpace) -> bool:
        """Return True if it is safe to remove dead code."""
        info = self.getInfo(spc)
        return self._pass > info.deadcodedelay

    def deadRemovalAllowedSeen(self, spc: AddrSpace) -> bool:
        """Check if dead code removal is safe and mark that removal has happened."""
        info = self.getInfo(spc)
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
        for i, vn in enumerate(read):
            descs = vn.getDescend()
            if len(descs) == 0:
                continue
            op = descs[0]
            if len(descs) != 1:
                raise LowlevelError("Free varnode with multiple reads")
            if vn.getSize() < size:
                if _heritage_debug_enabled():
                    _debug_heritage(
                        "guard.read "
                        f"range={addr.getSpace().getName()}[{addr.getOffset():#x}:{size}] "
                        f"vn={_format_vn_debug(vn)} "
                        f"follow=@{op.getAddr().getOffset():#x} "
                        f"opc={op.code()}"
                    )
                read[i] = vn = self.normalizeReadSize(vn, op, addr, size)
            vn.setActiveHeritage()
        for i, vn in enumerate(write):
            if vn.getSize() < size:
                if _heritage_debug_enabled():
                    op = vn.getDef()
                    _debug_heritage(
                        "guard.write "
                        f"range={addr.getSpace().getName()}[{addr.getOffset():#x}:{size}] "
                        f"vn={_format_vn_debug(vn)} "
                        f"def=@{op.getAddr().getOffset():#x} "
                        f"opc={op.code()}"
                    )
                write[i] = vn = self.normalizeWriteSize(vn, addr, size)
            vn.setActiveHeritage()
        if guardPerformed:
            fl_ref = [0]
            self._fd.getScopeLocal().queryProperties(addr, size, Address(), fl_ref)
            fl = fl_ref[0]
            self.guardCalls(fl, addr, size, write)
            self.guardReturns(fl, addr, size, write)
            if self._fd.getArch().highPtrPossible(addr, size):
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
        self.concatPieces(newinput, None, newout).setActiveHeritage()

    def guardCalls(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard CALL/CALLIND ops in preparation for renaming algorithm.

        For each call site, determine the effect on the given address range
        and insert appropriate INDIRECT or INDIRECT-creation ops. Also handle
        active input/output parameter analysis paths.

        C++ ref: ``Heritage::guardCalls``
        """
        from ghidra.fspec.fspec import EffectRecord, FuncCallSpecs, ParamEntry
        from ghidra.ir.varnode import Varnode as VnCls
        effect_name_to_type = {
            "unaffected": EffectRecord.unaffected,
            "killedbycall": EffectRecord.killedbycall,
            "return_address": EffectRecord.return_address,
            "unknown": EffectRecord.unknown_effect,
        }
        holdind = (fl & VnCls.addrtied) != 0
        for i in range(self._fd.numCalls()):
            fc = self._fd.getCallSpecs(i)
            # Skip if call already has an assignment matching exactly
            callOp = fc.getOp()
            if callOp.isAssignment():
                outvn = callOp.getOut()
                if outvn.getAddr() == addr and outvn.getSize() == size:
                    continue

            spc = addr.getSpace()
            off = addr.getOffset()
            tryregister = True
            if spc.getType() == IPTR_SPACEBASE:
                if fc.getSpacebaseOffset() != FuncCallSpecs.offset_unknown:
                    off = spc.wrapOffset(off - fc.getSpacebaseOffset())
                else:
                    tryregister = False
            transAddr = Address(spc, off)

            effecttype = fc.hasEffect(transAddr, size)
            if isinstance(effecttype, str):
                effecttype = effect_name_to_type.get(effecttype, EffectRecord.unknown_effect)

            possibleoutput = False

            # Active output path
            if fc.isOutputActive() and tryregister:
                active = fc.getActiveOutput()
                outputCharacter = fc.characterizeAsOutput(transAddr, size)
                if outputCharacter != ParamEntry.no_containment:
                    if effecttype != EffectRecord.killedbycall and fc.isAutoKilledByCall():
                        effecttype = EffectRecord.killedbycall
                    if outputCharacter == ParamEntry.contained_by:
                        if self.tryOutputOverlapGuard(fc, addr, transAddr, size, write):
                            effecttype = EffectRecord.unaffected
                    else:
                        if active.whichTrial(transAddr, size) < 0:
                            active.registerTrial(transAddr, size)
                            possibleoutput = True
            elif fc.isStackOutputLock() and tryregister:
                outputCharacter = fc.characterizeAsOutput(transAddr, size)
                if outputCharacter != ParamEntry.no_containment:
                    effecttype = EffectRecord.unknown_effect
                    if self.tryOutputStackGuard(fc, addr, transAddr, size, outputCharacter, write):
                        effecttype = EffectRecord.unaffected

            # Active input path
            if fc.isInputActive() and tryregister:
                inputCharacter = fc.characterizeAsInputParam(transAddr, size)
                if inputCharacter == ParamEntry.contains_justified:
                    active = fc.getActiveInput()
                    if active.whichTrial(transAddr, size) < 0:
                        active.registerTrial(transAddr, size)
                        vn = self._fd.newVarnode(size, addr)
                        vn.setActiveHeritage()
                        self._fd.opInsertInput(callOp, vn, callOp.numInput())
                elif inputCharacter == ParamEntry.contained_by:
                    self.guardCallOverlappingInput(fc, addr, transAddr, size)

            # Insert INDIRECT ops based on effect type
            if effecttype in (EffectRecord.unknown_effect, EffectRecord.return_address):
                indop = self._fd.newIndirectOp(callOp, addr, size, 0)
                indop.getIn(0).setActiveHeritage()
                indop.getOut().setActiveHeritage()
                write.append(indop.getOut())
                if holdind:
                    indop.getOut().setAddrForce()
                if effecttype == EffectRecord.return_address:
                    indop.getOut().setReturnAddress()
            elif effecttype == EffectRecord.killedbycall:
                indop = self._fd.newIndirectCreation(callOp, addr, size, possibleoutput)
                indop.getOut().setActiveHeritage()
                write.append(indop.getOut())

    def guardStores(self, addr: Address, size: int, write: list) -> None:
        """Guard STORE ops in preparation for the renaming algorithm."""
        from ghidra.ir.op import PcodeOp
        spc = addr.getSpace()
        container = spc.getContain()
        for op in self._fd.beginOp(OpCode.CPUI_STORE):
            if op.isDead():
                continue
            storeSpc = op.getIn(0).getSpaceFromConst()
            if (container is storeSpc and op.usesSpacebasePtr()) or (spc is storeSpc):
                indop = self._fd.newIndirectOp(op, addr, size, PcodeOp.indirect_store)
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
        # Active output path: check if this range could be a return value
        active = self._fd.getActiveOutput()
        if active is not None:
            from ghidra.fspec.fspec import ParamEntry
            outputCharacter = self._fd.getFuncProto().characterizeAsOutput(addr, size)
            if outputCharacter == ParamEntry.contained_by:
                self.guardReturnsOverlapping(addr, size)
            elif outputCharacter != ParamEntry.no_containment:
                active.registerTrial(addr, size)
                for op in self._fd.beginOp(OpCode.CPUI_RETURN):
                    if op.isDead():
                        continue
                    if op.getHaltType() != 0:
                        continue
                    invn = self._fd.newVarnode(size, addr)
                    invn.setActiveHeritage()
                    self._fd.opInsertInput(op, invn, op.numInput())
        # Persist path: force data-flow to persist through returns
        if (fl & VnCls.persist) == 0:
            return
        for op in self._fd.beginOp(OpCode.CPUI_RETURN):
            if op.isDead():
                continue
            copyop = self._fd.newOp(1, op.getAddr())
            vn = self._fd.newVarnodeOut(size, addr, copyop)
            vn.setAddrForce()
            vn.setActiveHeritage()
            self._fd.opSetOpcode(copyop, OpCode.CPUI_COPY)
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
        vData = VarnodeData()
        if not self._fd.getFuncProto().getBiggestContainedOutput(addr, size, vData):
            return
        truncAddr = Address(vData.space, vData.offset)
        active = self._fd.getActiveOutput()
        active.registerTrial(truncAddr, vData.size)
        # Calculate truncation offset
        offset = vData.offset - addr.getOffset()
        if vData.space.isBigEndian():
            offset = (size - vData.size) - offset
        for op in self._fd.beginOp(OpCode.CPUI_RETURN):
            if op.isDead():
                continue
            if op.getHaltType() != 0:
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
        vData = VarnodeData()
        if fc.getBiggestContainedInputParam(transAddr, size, vData):
            active = fc.getActiveInput()
            truncAddr = Address(vData.space, vData.offset)
            diff = truncAddr.getOffset() - transAddr.getOffset()
            truncAddr = addr + diff
            if active.whichTrial(truncAddr, size) < 0:
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
            slotNew = 0 if retAddr.isBigEndian() else 1
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
            slotNew = 1 if retAddr.isBigEndian() else 0
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
        vData = VarnodeData()
        if not fc.getBiggestContainedOutput(transAddr, size, vData):
            return False
        active = fc.getActiveOutput()
        truncAddr = Address(vData.space, vData.offset)
        diff = truncAddr.getOffset() - transAddr.getOffset()
        truncAddr = addr + diff  # Convert to caller's perspective
        if active.whichTrial(truncAddr, size) >= 0:
            return False  # Trial already exists
        self.guardOutputOverlap(fc.getOp(), addr, size, truncAddr, vData.size, write)
        active.registerTrial(truncAddr, vData.size)
        return True

    def tryOutputStackGuard(self, fc, addr, transAddr, size, outputCharacter, write) -> bool:
        """Guard a stack range against a call that returns a value overlapping that range.

        C++ ref: ``Heritage::tryOutputStackGuard``
        """
        from ghidra.fspec.fspec import ParamEntry
        callOp = fc.getOp()
        if outputCharacter == ParamEntry.contained_by:
            vData = VarnodeData()
            if not fc.getBiggestContainedOutput(transAddr, size, vData):
                return False
            truncAddr = Address(vData.space, vData.offset)
            diff = truncAddr.getOffset() - transAddr.getOffset()
            truncAddr = addr + diff
            self.guardOutputOverlapStack(callOp, addr, size, truncAddr, vData.size, write)
            return True
        # Reaching here, output exists and contains the heritage range
        retOut = fc.getOutput()
        retAddr = retOut.getAddress()
        diff = addr.getOffset() - transAddr.getOffset()
        retAddr = retAddr + diff  # Translate to caller perspective
        retSize = retOut.getSize()
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
            slotNew = 0 if retAddr.isBigEndian() else 1
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
            slotNew = 1 if retAddr.isBigEndian() else 0
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
        start = memrange.addr.getOffset()
        endaddr = memrange.addr + memrange.size
        wraparound = endaddr.getOffset() < start
        target_space = memrange.addr.getSpace()
        maxsize = 0

        for vn in self._fd.beginLoc():
            vnaddr = vn.getAddr()
            if vnaddr < memrange.addr:
                continue
            if wraparound:
                if vn.getSpace() is not target_space:
                    break
            else:
                if not (vnaddr < endaddr):
                    break

            if vn.isWriteMask():
                continue
            if vn.isWritten():
                op = vn.getDef()
                if op.isMarker() or op.isReturnCopy():
                    if vn.getSize() < memrange.size:
                        remove.append(vn)
                        continue
                    memrange.clearProperty(MemRange.new_addresses)
                if vn.getSize() > maxsize:
                    maxsize = vn.getSize()
                write.append(vn)
            elif (not vn.isHeritageKnown()) and (not vn.hasNoDescend()):
                read.append(vn)
            elif vn.isInput():
                inputvars.append(vn)

        if _heritage_debug_range_matches(memrange.addr, memrange.size):
            _debug_heritage(
                "collect "
                f"range={_format_range_debug(memrange.addr, memrange.size)} "
                f"maxsize={maxsize} "
                f"read={_format_vn_list_debug(read)} "
                f"write={_format_vn_list_debug(write)} "
                f"input={_format_vn_list_debug(inputvars)} "
                f"remove={_format_vn_list_debug(remove)}"
            )
        return maxsize

    def normalizeReadSize(self, vn, op, addr: Address, size: int):
        """Normalize the size of a read Varnode, prior to heritage."""
        newop = self._fd.newOp(2, op.getAddr())
        self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
        vn1 = self._fd.newVarnode(size, addr)
        overlap = vn.overlap(addr, size)
        vn2 = self._fd.newConstant(addr.getAddrSize(), overlap)
        self._fd.opSetInput(newop, vn1, 0)
        self._fd.opSetInput(newop, vn2, 1)
        self._fd.opSetOutput(newop, vn)
        newop.getOut().setWriteMask()
        if _heritage_debug_enabled():
            _debug_heritage(
                "normalizeReadSize "
                f"range={addr.getSpace().getName()}[{addr.getOffset():#x}:{size}] "
                f"read={_format_vn_debug(vn)} "
                f"follow=@{op.getAddr().getOffset():#x} "
                f"newin={_format_vn_debug(vn1)}"
            )
        self._fd.opInsertBefore(newop, op)
        return vn1

    def normalizeWriteSize(self, vn, addr: Address, size: int):
        """Normalize the size of a written Varnode, prior to heritage.

        Given a Varnode that is written that does not match the (larger) size
        of the address range currently being linked, create the missing pieces
        and concatenate everything into a new Varnode of the correct size.
        """
        op = vn.getDef()
        overlap = vn.overlap(addr, size)
        mostsigsize = size - (overlap + vn.getSize())

        mostvn = None
        leastvn = None
        bigendian = addr.isBigEndian()

        # Create most significant piece if needed
        if mostsigsize != 0:
            if bigendian:
                pieceaddr = addr
            else:
                pieceaddr = addr + (overlap + vn.getSize())

            if op.isCall() and self.callOpIndirectEffect(pieceaddr, mostsigsize, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, mostsigsize, False)
                mostvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                mostvn = self._fd.newVarnodeOut(mostsigsize, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                self._fd.opSetInput(newop, self._fd.newConstant(addr.getAddrSize(), overlap + vn.getSize()), 1)
                if _heritage_debug_enabled():
                    _debug_heritage(
                        "normalizeWriteSize.most "
                        f"range={addr.getSpace().getName()}[{addr.getOffset():#x}:{size}] "
                        f"write={_format_vn_debug(vn)} "
                        f"piece={_format_vn_debug(mostvn)} "
                        f"follow=@{op.getAddr().getOffset():#x}"
                    )
                self._fd.opInsertBefore(newop, op)

        # Create least significant piece if needed
        if overlap != 0:
            if bigendian:
                pieceaddr = addr + (size - overlap)
            else:
                pieceaddr = addr

            if op.isCall() and self.callOpIndirectEffect(pieceaddr, overlap, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, overlap, False)
                leastvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                leastvn = self._fd.newVarnodeOut(overlap, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                self._fd.opSetInput(newop, self._fd.newConstant(addr.getAddrSize(), 0), 1)
                if _heritage_debug_enabled():
                    _debug_heritage(
                        "normalizeWriteSize.least "
                        f"range={addr.getSpace().getName()}[{addr.getOffset():#x}:{size}] "
                        f"write={_format_vn_debug(vn)} "
                        f"piece={_format_vn_debug(leastvn)} "
                        f"follow=@{op.getAddr().getOffset():#x}"
                    )
                self._fd.opInsertBefore(newop, op)

        # Concatenate least significant piece with vn
        if overlap != 0:
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
        if mostsigsize != 0:
            newop = self._fd.newOp(2, op.getAddr())
            bigout = self._fd.newVarnodeOut(size, addr, newop)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            self._fd.opSetInput(newop, mostvn, 0)
            self._fd.opSetInput(newop, midvn, 1)
            self._fd.opInsertAfter(newop, midvn.getDef())
        else:
            bigout = midvn

        vn.setWriteMask()
        return bigout

    def concatPieces(self, vnlist: list, insertop, finalvn):
        """Concatenate a list of Varnodes together using PIECE ops."""
        preexist = vnlist[0]
        bigendian = preexist.getAddr().isBigEndian()
        if insertop is None:
            bl = self._fd.getBasicBlocks().getStartBlock()
            insert_pos = 0
            opaddr = self._fd.getAddress()
        else:
            bl = insertop.getParent()
            insert_pos = bl.getOpList().index(insertop)
            opaddr = insertop.getAddr()
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
            self._fd.opInsert(newop, bl, insert_pos)
            insert_pos += 1
            preexist = newvn
        return preexist

    def splitPieces(self, vnlist: list, insertop, addr: Address, size: int, startvn) -> None:
        """Build a set of Varnode piece expressions at the given location."""
        bigendian = addr.isBigEndian()
        baseoff = addr.getOffset() + size if bigendian else addr.getOffset()
        if insertop is None:
            bl = self._fd.getBasicBlocks().getStartBlock()
            insert_pos = 0
            opaddr = self._fd.getAddress()
        else:
            bl = insertop.getParent()
            insert_pos = bl.getOpList().index(insertop) + 1
            opaddr = insertop.getAddr()
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
            self._fd.opInsert(newop, bl, insert_pos)
            insert_pos += 1

    @staticmethod
    def buildRefinement(refine: list, addr: Address, vnlist: list) -> None:
        """Build a refinement array given an address range and a list of Varnodes."""
        for vn in vnlist:
            curaddr = vn.getAddr()
            sz = vn.getSize()
            diff = curaddr.getOffset() - addr.getOffset()
            refine[diff] = 1
            refine[diff + sz] = 1

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
        diff = spc.wrapOffset(curaddr.getOffset() - addr.getOffset())
        cutsz = refine[diff]
        if sz <= cutsz:
            return  # Already refined
        split.append(self._fd.newVarnode(cutsz, curaddr))
        sz -= cutsz
        while sz > 0:
            curaddr = curaddr + cutsz
            diff = spc.wrapOffset(curaddr.getOffset() - addr.getOffset())
            cutsz = refine[diff]
            if cutsz > sz:
                cutsz = sz
            split.append(self._fd.newVarnode(cutsz, curaddr))
            sz -= cutsz

    def refineRead(self, vn, addr: Address, refine: list, newvn: list) -> None:
        """Split up a free Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        concatenated via PIECE ops. The original Varnode is replaced with a
        temporary holding the concatenated result.

        C++ ref: ``Heritage::refineRead``
        """
        newvn.clear()
        self.splitByRefinement(vn, addr, refine, newvn)
        if not newvn:
            return
        replacevn = self._fd.newUnique(vn.getSize())
        op = vn.loneDescend()
        slot = op.getSlot(vn)
        self.concatPieces(newvn, op, replacevn)
        self._fd.opSetInput(op, replacevn, slot)
        if vn.hasNoDescend():
            self._fd.deleteVarnode(vn)
        else:
            raise LowlevelError("Refining non-free varnode")

    def refineWrite(self, vn, addr: Address, refine: list, newvn: list) -> None:
        """Split up an output Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        each defined by a SUBPIECE op. The original Varnode is replaced with
        a temporary.

        C++ ref: ``Heritage::refineWrite``
        """
        newvn.clear()
        self.splitByRefinement(vn, addr, refine, newvn)
        if not newvn:
            return
        replacevn = self._fd.newUnique(vn.getSize())
        defop = vn.getDef()
        self._fd.opSetOutput(defop, replacevn)
        self.splitPieces(newvn, defop, vn.getAddr(), vn.getSize(), replacevn)
        self._fd.totalReplace(vn, replacevn)
        self._fd.deleteVarnode(vn)

    def refineInput(self, vn, addr: Address, refine: list, newvn: list) -> None:
        """Split up a known input Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        each defined by a SUBPIECE op.

        C++ ref: ``Heritage::refineInput``
        """
        newvn.clear()
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
            if _heritage_debug_range_matches(addr, size):
                _debug_heritage(
                    "refinement.skip "
                    f"range={_format_range_debug(addr, size)} "
                    f"refine={refine} "
                    f"read={_format_vn_list_debug(readvars)} "
                    f"write={_format_vn_list_debug(writevars)} "
                    f"input={_format_vn_list_debug(inputvars)}"
                )
            return -1  # No non-trivial refinements
        refine[lastpos] = size - lastpos
        self.remove13Refinement(refine)
        if _heritage_debug_range_matches(addr, size):
            _debug_heritage(
                "refinement "
                f"range={_format_range_debug(addr, size)} "
                f"refine={refine} "
                f"read={_format_vn_list_debug(readvars)} "
                f"write={_format_vn_list_debug(writevars)} "
                f"input={_format_vn_list_debug(inputvars)}"
            )
        newvn = []
        for vn in readvars:
            self.refineRead(vn, addr, refine, newvn)
        for vn in writevars:
            self.refineWrite(vn, addr, refine, newvn)
        for vn in inputvars:
            self.refineInput(vn, addr, refine, newvn)

        # Alter the disjoint cover to reflect our refinement (C++ heritage.cc:1920-1938)
        flags = memrange.flags
        self._disjoint.erase(idx)
        giter = self._globaldisjoint.find(addr)
        curPass = giter[1].pass_
        self._globaldisjoint.erase(giter)
        cut = 0
        sz = refine[cut]
        curaddr = addr
        new_ranges = [_format_range_debug(curaddr, sz)] if _heritage_debug_range_matches(addr, size) else None
        res_idx = self._disjoint.insert(idx, curaddr, sz, flags)
        intersect = [0]
        self._globaldisjoint.add(curaddr, sz, curPass, intersect)
        cut += sz
        curaddr = addr + cut
        insert_pos = idx + 1
        while cut < size:
            sz = refine[cut]
            self._disjoint.insert(insert_pos, curaddr, sz, flags)
            self._globaldisjoint.add(curaddr, sz, curPass, intersect)
            if new_ranges is not None:
                new_ranges.append(_format_range_debug(curaddr, sz))
            cut += sz
            curaddr = addr + cut
            insert_pos += 1
        if new_ranges is not None:
            _debug_heritage(
                "refinement.result "
                f"range={_format_range_debug(addr, size)} "
                f"split={new_ranges}"
            )
        return res_idx

    def callOpIndirectEffect(self, addr: Address, size: int, op) -> bool:
        """Determine if the address range is affected by the given call p-code op."""
        if op.code() in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            fc = self._fd.getCallSpecs(op)
            if fc is None:
                return True
            return fc.hasEffectTranslate(addr, size) != 'unaffected'
        return False

    def bumpDeadcodeDelay(self, spc: AddrSpace) -> None:
        """Increase the heritage delay for the given AddrSpace and request a restart."""
        if spc.getType() not in (IPTR_PROCESSOR, IPTR_SPACEBASE):
            return
        if spc.getDelay() != spc.getDeadcodeDelay():
            return
        override = self._fd.getOverride()
        if override.hasDeadcodeDelay(spc):
            return
        override.insertDeadcodeDelay(spc, spc.getDeadcodeDelay() + 1)
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
        if info.deadremoved > 0:
            self.bumpDeadcodeDelay(addr.getSpace())
            if not info.warningissued:
                info.warningissued = True
                self._fd.warningHeader(f"Heritage AFTER dead removal. Revisit: {addr}")

        newInputs = []
        for vn in remove:
            op = vn.getDef()
            bl = op.getParent()
            if op.code() == OpCode.CPUI_INDIRECT:
                iopVn = op.getIn(1)
                from ghidra.ir.op import PcodeOp as PcodeOpCls
                targetOp = PcodeOpCls.getOpFromConst(iopVn.getAddr())
                if targetOp.isDead():
                    pos = bl.getOpList().index(op) + 1
                else:
                    pos = bl.getOpList().index(targetOp) + 1
                vn.clearAddrForce()
            elif op.code() == OpCode.CPUI_MULTIEQUAL:
                pos = bl.getOpList().index(op) + 1
                while pos < len(bl.getOpList()) and bl.getOpList()[pos].code() == OpCode.CPUI_MULTIEQUAL:
                    pos += 1
            else:
                self._fd.opUnlink(op)
                continue

            offset = vn.overlap(addr, size)
            self._fd.opUninsert(op)
            newInputs.clear()
            big = self._fd.newVarnode(size, addr)
            big.setActiveHeritage()
            newInputs.append(big)
            newInputs.append(self._fd.newConstant(4, offset))
            self._fd.opSetOpcode(op, OpCode.CPUI_SUBPIECE)
            self._fd.opSetAllInput(op, newInputs)
            self._fd.opInsert(op, bl, pos)
            vn.setWriteMask()

    def clearStackPlaceholders(self, info: HeritageInfo) -> None:
        """Clear any placeholder LOADs associated with calls."""
        numCalls = self._fd.numCalls()
        for i in range(numCalls):
            self._fd.getCallSpecs(i).abortSpacebaseRelative(self._fd)
        info.hasCallPlaceholders = False

    def processJoins(self) -> None:
        """Split join-space Varnodes into their real components.

        Any free Varnode in join-space is split into its real register pieces
        using PIECE ops. Written join-space Varnodes are split via SUBPIECE.
        This ensures join-space addresses play no role in the heritage process.

        C++ ref: ``Heritage::processJoins``
        """
        arch = self._fd.getArch()
        joinspace = arch.getJoinSpace()
        for vn in self._fd.beginLoc(joinspace):
            if vn.getSpace() is not joinspace:
                break
            joinrec = arch.findJoin(vn.getOffset())
            piecespace = joinrec.getPiece(0).space

            if joinrec.getUnified().size != vn.getSize():
                raise LowlevelError("Joined varnode does not match size of record")
            if vn.isFree():
                if joinrec.isFloatExtension():
                    self.floatExtensionRead(vn, joinrec)
                else:
                    self.splitJoinRead(vn, joinrec)

            info = self.getInfo(piecespace)
            if self._pass != info.delay:
                continue

            if joinrec.isFloatExtension():
                self.floatExtensionWrite(vn, joinrec)
            else:
                self.splitJoinWrite(vn, joinrec)

    def splitJoinLevel(self, lastcombo: list, nextlev: list, joinrec) -> None:
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

    def splitJoinRead(self, vn, joinrec) -> None:
        """Construct pieces for a join-space Varnode read by an operation.

        Given a splitting specification (JoinRecord) and a Varnode, build a
        concatenation expression (out of PIECE operations) that constructs
        the Varnode out of the specified Varnode pieces.

        C++ ref: ``Heritage::splitJoinRead``
        """
        op = vn.loneDescend()
        isPrimitive = True
        if vn.isTypeLock():
            isPrimitive = vn.getType().isPrimitiveWhole()

        lastcombo = [vn]
        while len(lastcombo) < joinrec.numPieces():
            nextlev = []
            self.splitJoinLevel(lastcombo, nextlev, joinrec)
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
                    mosthalf.setPrecisHi()
                    leasthalf.setPrecisLo()
                else:
                    self._fd.opMarkNoCollapse(concat)
                op = concat  # Keep op as earliest in concatenation construction
            lastcombo = [v for v in nextlev if v is not None]

    def splitJoinWrite(self, vn, joinrec) -> None:
        """Split a written join-space Varnode into specified pieces.

        Given a splitting specification (JoinRecord) and a Varnode, build a
        series of expressions that construct the specified Varnode pieces
        using SUBPIECE ops.

        C++ ref: ``Heritage::splitJoinWrite``
        """
        op = vn.getDef()
        bb = self._fd.getBasicBlocks().getBlock(0)
        isPrimitive = True
        if vn.isTypeLock():
            isPrimitive = vn.getType().isPrimitiveWhole()

        lastcombo = [vn]
        while len(lastcombo) < joinrec.numPieces():
            nextlev = []
            self.splitJoinLevel(lastcombo, nextlev, joinrec)
            for i in range(len(lastcombo)):
                curvn = lastcombo[i]
                mosthalf = nextlev[2 * i]
                leasthalf = nextlev[2 * i + 1]
                if leasthalf is None:
                    continue  # Varnode didn't get split this level
                if vn.isInput():
                    split = self._fd.newOp(2, bb.getStart())
                else:
                    split = self._fd.newOp(2, op.getAddr())
                self._fd.opSetOpcode(split, OpCode.CPUI_SUBPIECE)
                self._fd.opSetOutput(split, mosthalf)
                self._fd.opSetInput(split, curvn, 0)
                self._fd.opSetInput(split, self._fd.newConstant(4, leasthalf.getSize()), 1)
                if op is None:
                    self._fd.opInsertBegin(split, bb)
                else:
                    self._fd.opInsertAfter(split, op)
                op = split  # Keep op as latest in split construction
                split2 = self._fd.newOp(2, op.getAddr())
                self._fd.opSetOpcode(split2, OpCode.CPUI_SUBPIECE)
                self._fd.opSetOutput(split2, leasthalf)
                self._fd.opSetInput(split2, curvn, 0)
                self._fd.opSetInput(split2, self._fd.newConstant(4, 0), 1)
                self._fd.opInsertAfter(split2, op)
                if isPrimitive:
                    mosthalf.setPrecisHi()
                    leasthalf.setPrecisLo()
                op = split2  # Keep op as latest in split construction
            lastcombo = [v for v in nextlev if v is not None]

    def floatExtensionRead(self, vn, joinrec) -> None:
        """Create float truncation into a free lower precision join-space Varnode.

        Given a Varnode with logically lower precision, as given by a float
        extension record (JoinRecord), create the real full-precision Varnode
        and define the lower precision Varnode as a truncation (FLOAT2FLOAT).

        C++ ref: ``Heritage::floatExtensionRead``
        """
        op = vn.loneDescend()
        trunc = self._fd.newOp(1, op.getAddr())
        vdata = joinrec.getPiece(0)  # Float extensions have exactly 1 piece
        bigvn = self._fd.newVarnode(vdata.size, vdata.getAddr())
        self._fd.opSetOpcode(trunc, OpCode.CPUI_FLOAT_FLOAT2FLOAT)
        self._fd.opSetOutput(trunc, vn)
        self._fd.opSetInput(trunc, bigvn, 0)
        self._fd.opInsertBefore(trunc, op)

    def floatExtensionWrite(self, vn, joinrec) -> None:
        """Create float extension from a lower precision join-space Varnode.

        Given a Varnode with logically lower precision, as given by a float
        extension record (JoinRecord), create the full precision Varnode
        specified by the record, making it defined by an extension (FLOAT2FLOAT).

        C++ ref: ``Heritage::floatExtensionWrite``
        """
        op = vn.getDef()
        bb = self._fd.getBasicBlocks().getBlock(0)
        if vn.isInput():
            ext = self._fd.newOp(1, bb.getStart())
        else:
            ext = self._fd.newOp(1, op.getAddr())
        vdata = joinrec.getPiece(0)  # Float extensions have exactly 1 piece
        self._fd.opSetOpcode(ext, OpCode.CPUI_FLOAT_FLOAT2FLOAT)
        self._fd.newVarnodeOut(vdata.size, vdata.getAddr(), ext)
        self._fd.opSetInput(ext, vn, 0)
        if op is None:
            self._fd.opInsertBegin(ext, bb)
        else:
            self._fd.opInsertAfter(ext, op)

    def generateLoadGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed LOAD into a stack space."""
        if not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.offset)
            self._loadGuard.append(guard)
            self._fd.opMarkSpacebasePtr(op)

    def generateStoreGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed STORE to a stack space."""
        if not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.offset)
            self._storeGuard.append(guard)
            self._fd.opMarkSpacebasePtr(op)

    def protectFreeStores(self, spc: AddrSpace, freeStores: list) -> bool:
        """Identify any STORE ops that use a free pointer from a given address space.

        Walk through all STORE ops. For each, trace the pointer input back
        through COPYs and constant INT_ADDs. If the base pointer is free and
        lives in the given space, mark the STORE as spacebase and add it to
        the freeStores list.

        C++ ref: ``Heritage::protectFreeStores``
        """
        hasNew = False
        for op in self._fd.beginOp(OpCode.CPUI_STORE):
            if op.isDead():
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
            if vn.isFree() and vn.getSpace() == spc:
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
        markedVn = []
        path = []
        unknownStackStorage = False

        for i in range(spc.numSpacebase()):
            stackPointer = spc.getSpacebase(i)
            spInput = self._fd.findVarnodeInput(stackPointer.size, stackPointer.getAddr())
            if spInput is None:
                continue
            path.append(StackNode(spInput, 0, 0))
            while path:
                curNode = path[-1]
                if curNode.iter >= len(curNode.descend):
                    path.pop()
                    continue
                op = curNode.descend[curNode.iter]
                curNode.iter += 1
                outVn = op.getOut()
                if outVn is not None and outVn.isMark():
                    continue
                opc = op.code()
                if opc == OpCode.CPUI_INT_ADD:
                    otherSlot = 1 - op.getSlot(curNode.vn)
                    otherVn = op.getIn(otherSlot)
                    if otherVn.isConstant():
                        newOffset = spc.wrapOffset(curNode.offset + otherVn.getOffset())
                        nextNode = StackNode(outVn, newOffset, curNode.traversals)
                        if nextNode.iter < len(nextNode.descend):
                            outVn.setMark()
                            path.append(nextNode)
                            markedVn.append(outVn)
                        elif outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                    else:
                        nextNode = StackNode(outVn, curNode.offset, curNode.traversals | StackNode.nonconstant_index)
                        if nextNode.iter < len(nextNode.descend):
                            outVn.setMark()
                            path.append(nextNode)
                            markedVn.append(outVn)
                        elif outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                elif opc == OpCode.CPUI_SEGMENTOP:
                    if op.getIn(2) is not curNode.vn:
                        continue
                    nextNode = StackNode(outVn, curNode.offset, curNode.traversals)
                    if nextNode.iter < len(nextNode.descend):
                        outVn.setMark()
                        path.append(nextNode)
                        markedVn.append(outVn)
                    elif outVn.getSpace().getType() == IPTR_SPACEBASE:
                        unknownStackStorage = True
                elif opc in (OpCode.CPUI_INDIRECT, OpCode.CPUI_COPY):
                    nextNode = StackNode(outVn, curNode.offset, curNode.traversals)
                    if nextNode.iter < len(nextNode.descend):
                        outVn.setMark()
                        path.append(nextNode)
                        markedVn.append(outVn)
                    elif outVn.getSpace().getType() == IPTR_SPACEBASE:
                        unknownStackStorage = True
                elif opc == OpCode.CPUI_MULTIEQUAL:
                    nextNode = StackNode(outVn, curNode.offset, curNode.traversals | StackNode.multiequal)
                    if nextNode.iter < len(nextNode.descend):
                        outVn.setMark()
                        path.append(nextNode)
                        markedVn.append(outVn)
                    elif outVn.getSpace().getType() == IPTR_SPACEBASE:
                        unknownStackStorage = True
                elif opc == OpCode.CPUI_LOAD:
                    if curNode.traversals != 0:
                        self.generateLoadGuard(curNode, op, spc)
                elif opc == OpCode.CPUI_STORE:
                    if op.getIn(1) is curNode.vn:
                        if curNode.traversals != 0:
                            self.generateStoreGuard(curNode, op, spc)
                        else:
                            self._fd.opMarkSpacebasePtr(op)
                else:
                    continue

        for vn in markedVn:
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
        for op in freeStores:
            self._fd.opClearSpacebasePtr(op)
        self.discoverIndexedStackPointers(spc, freeStores, False)
        for op in freeStores:
            if op.usesSpacebasePtr():
                continue
            indOp = op.previousOp()
            while indOp is not None:
                if indOp.code() != OpCode.CPUI_INDIRECT:
                    break
                iopVn = indOp.getIn(1)
                from ghidra.core.space import IPTR_IOP
                if iopVn.getSpace().getType() != IPTR_IOP:
                    break
                from ghidra.ir.op import PcodeOp
                if op is not PcodeOp.getOpFromConst(iopVn.getAddr()):
                    break
                nextOp = indOp.previousOp()
                if indOp.getOut().getSpace() == spc:
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
                if vn.isAddrForce():
                    continue  # Already address forced
                newOp = vn.getDef()
                if newOp.isMark():
                    continue  # Already visited
                newOp.setMark()
                opc = newOp.code()
                isArtificial = False
                if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_MULTIEQUAL:
                    isArtificial = True
                    maxInNew = newOp.numInput()
                    for j in range(maxInNew):
                        inVn = newOp.getIn(j)
                        if addr != inVn.getAddr():
                            isArtificial = False
                            break
                elif opc == OpCode.CPUI_INDIRECT and newOp.isIndirectStore():
                    inVn = newOp.getIn(0)
                    if addr == inVn.getAddr():
                        isArtificial = True
                if isArtificial:
                    copySinks.append(newOp)
                else:
                    forces.append(newOp)

    def propagateCopyAway(self, op) -> None:
        """Eliminate a COPY sink preserving its data-flow."""
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
            loadRanges = RangeList()
            for guard in self._loadGuard:
                loadRanges.insertRange(guard.spc, guard.minimumOffset, guard.maximumOffset)
            for op in forces:
                vn = op.getOut()
                if loadRanges.inRange(vn.getAddr(), 1):
                    vn.setAddrForce()
                op.clearMark()
        # Eliminate original COPY sinks
        for i in range(copySinkSize):
            op = self._loadCopyOps[i]
            self.propagateCopyAway(op)
        # Clear marks on remaining artificial COPYs
        for i in range(copySinkSize, len(self._loadCopyOps)):
            op = self._loadCopyOps[i]
            op.clearMark()
        self._loadCopyOps.clear()

    def analyzeNewLoadGuards(self) -> None:
        """Make final determination of what range new LoadGuards are protecting.

        C++ ref: ``Heritage::analyzeNewLoadGuards``
        """
        nothingToDo = True
        if self._loadGuard:
            if self._loadGuard[-1].analysisState == 0:
                nothingToDo = False
        if self._storeGuard:
            if self._storeGuard[-1].analysisState == 0:
                nothingToDo = False
        if nothingToDo:
            return

        sinks = []
        reads = []

        loadStart = len(self._loadGuard)
        while loadStart > 0:
            guard = self._loadGuard[loadStart - 1]
            if guard.analysisState != 0:
                break
            loadStart -= 1
            reads.append(guard.op)
            sinks.append(guard.op.getIn(1))

        storeStart = len(self._storeGuard)
        while storeStart > 0:
            guard = self._storeGuard[storeStart - 1]
            if guard.analysisState != 0:
                break
            storeStart -= 1
            reads.append(guard.op)
            sinks.append(guard.op.getIn(1))

        stackSpc = self._fd.getArch().getStackSpace()
        stackReg = None
        if stackSpc is not None and stackSpc.numSpacebase() > 0:
            stackReg = self._fd.findSpacebaseInput(stackSpc)

        vsSolver = ValueSetSolver()
        vsSolver.establishValueSets(sinks, reads, stackReg, False)
        widener = WidenerNone()
        vsSolver.solve(10000, widener)

        runFullAnalysis = False
        for guard in self._loadGuard[loadStart:]:
            guard.establishRange(vsSolver.getValueSetRead(guard.op.getSeqNum()))
            if guard.analysisState == 0:
                runFullAnalysis = True
        for guard in self._storeGuard[storeStart:]:
            guard.establishRange(vsSolver.getValueSetRead(guard.op.getSeqNum()))
            if guard.analysisState == 0:
                runFullAnalysis = True

        if runFullAnalysis:
            fullWidener = WidenerFull()
            vsSolver.solve(10000, fullWidener)
            for guard in self._loadGuard[loadStart:]:
                guard.finalizeRange(vsSolver.getValueSetRead(guard.op.getSeqNum()))
            for guard in self._storeGuard[storeStart:]:
                guard.finalizeRange(vsSolver.getValueSetRead(guard.op.getSeqNum()))

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
        a = [0] * size
        b = [0] * size
        t = [0] * size
        z = [0] * size
        upstart = []
        upend = []

        self._augment.clear()
        self._augment = [[] for _ in range(size)]
        self._flags.clear()
        self._flags = [0] * size

        self._domchild = graph.buildDomTree()
        self._depth, self._maxdepth = graph.buildDomDepth()

        for i in range(size):
            x = graph.getBlock(i)
            for j in range(len(self._domchild[i])):
                v = self._domchild[i][j]
                for k in range(v.sizeIn()):
                    u = v.getIn(k)
                    if u is not v.getImmedDom():
                        upstart.append(u)
                        upend.append(v)
                        b[u.getIndex()] += 1
                        t[x.getIndex()] += 1

        for i in range(size - 1, -1, -1):
            k_sum = 0
            l_sum = 0
            for j in range(len(self._domchild[i])):
                child = self._domchild[i][j]
                k_sum += a[child.getIndex()]
                l_sum += z[child.getIndex()]
            a[i] = b[i] - t[i] + k_sum
            z[i] = 1 + l_sum
            if len(self._domchild[i]) == 0 or z[i] > a[i] + 1:
                self._flags[i] |= Heritage.boundary_node
                z[i] = 1

        if size == 0:
            return

        z[0] = -1
        for i in range(1, size):
            j = graph.getBlock(i).getImmedDom().getIndex()
            if (self._flags[j] & Heritage.boundary_node) != 0:
                z[i] = j
            else:
                z[i] = z[j]

        for i in range(len(upstart)):
            v = upend[i]
            j = v.getImmedDom().getIndex()
            k = upstart[i].getIndex()
            while j < k:
                self._augment[k].append(v)
                k = z[k]

    def visitIncr(self, qnode, vnode) -> None:
        """The heart of the phi-node placement algorithm."""
        i = vnode.getIndex()
        j = qnode.getIndex()
        for v in self._augment[i]:
            if v.getImmedDom().getIndex() < j:
                k = v.getIndex()
                if (self._flags[k] & Heritage.merged_node) == 0:
                    self._merge.append(v)
                    self._flags[k] |= Heritage.merged_node
                if (self._flags[k] & Heritage.mark_node) == 0:
                    self._flags[k] |= Heritage.mark_node
                    self._pq.insert(v, self._depth[k])
            else:
                break
        if (self._flags[i] & Heritage.boundary_node) == 0:
            for child in self._domchild[i]:
                if (self._flags[child.getIndex()] & Heritage.mark_node) == 0:
                    self.visitIncr(qnode, child)

    def calcMultiequals(self, write: list) -> None:
        """Calculate blocks that should contain MULTIEQUALs for one address range."""
        self._pq.reset(self._maxdepth)
        self._merge.clear()
        for vn in write:
            bl = vn.getDef().getParent()
            j = bl.getIndex()
            if (self._flags[j] & Heritage.mark_node) != 0:
                continue
            self._pq.insert(bl, self._depth[j])
            self._flags[j] |= Heritage.mark_node
        # Make sure start node is in input
        if (self._flags[0] & Heritage.mark_node) == 0:
            self._pq.insert(self._fd.getBasicBlocks().getBlock(0), self._depth[0])
            self._flags[0] |= Heritage.mark_node
        while not self._pq.empty():
            bl = self._pq.extract()
            self.visitIncr(bl, bl)
        for i in range(len(self._flags)):
            self._flags[i] &= ~(Heritage.mark_node | Heritage.merged_node)

    def placeMultiequals(self) -> None:
        """Perform phi-node placement for the current set of address ranges."""
        readvars: list = []
        writevars: list = []
        inputvars: list = []
        removevars: list = []

        # Use index-based iteration because refinement can modify the list
        idx = 0
        while idx < len(self._disjoint):
            memrange = self._disjoint[idx]
            if _heritage_debug_enabled():
                _debug_heritage(
                    "placeMultiequals "
                    f"idx={idx} range={memrange.addr.getSpace().getName()}[{memrange.addr.getOffset():#x}:{memrange.size}] "
                    f"flags={memrange.flags}"
                )
            maxsize = self.collect(memrange, readvars, writevars, inputvars, removevars)
            size = memrange.size
            if size > 4 and maxsize < size:
                ref_idx = self.refinement(idx, readvars, writevars, inputvars)
                if ref_idx >= 0:
                    idx = ref_idx
                    memrange = self._disjoint[idx]
                    self.collect(memrange, readvars, writevars, inputvars, removevars)
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
                for slot in range(op.numInput()):
                    vnin = op.getIn(slot)
                    if vnin.isHeritageKnown():
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
                        iop_addr = vnnew.getDef().getIn(1).getAddr()
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
                vnin = multiop.getIn(slot)
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
        for slot in range(len(self._domchild[bl_idx])):
            self.renameRecurse(self._domchild[bl_idx][slot], varstack)

        # Pop this block's writes off the stack
        for vnout in writelist:
            varstack[vnout.getAddr()].pop()

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
        if self._maxdepth == -1:
            self.buildADT()

        self.processJoins()
        from ghidra.analysis.prefersplit import PreferSplitManager

        splitmanage = PreferSplitManager()
        if self._pass == 0:
            splitmanage.init(self._fd, self._fd.getArch().splitrecords)
            splitmanage.split()

        reprocessStackCount = 0
        stackSpace = None
        freeStores: list = []

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
            for vn in self._fd.beginLoc(info.space):
                if (not vn.isWritten()) and vn.hasNoDescend() and (not vn.isUnaffected()) and (not vn.isInput()):
                    continue
                if vn.isWriteMask():
                    continue
                intersect_ref = [0]
                canon_addr, canon_sizepass = self._globaldisjoint.add(
                    vn.getAddr(), vn.getSize(), self._pass, intersect_ref
                )
                prev = intersect_ref[0]
                if prev == 0:
                    self._disjoint.add(canon_addr, canon_sizepass.size, MemRange.new_addresses)
                elif prev == 2:
                    if vn.isHeritageKnown():
                        continue
                    if vn.hasNoDescend():
                        continue
                    if (not needwarning) and (info.deadremoved > 0) and (not self._fd.isJumptableRecoveryOn()):
                        needwarning = True
                        self.bumpDeadcodeDelay(vn.getSpace())
                        warnvn = vn
                    self._disjoint.add(canon_addr, canon_sizepass.size, MemRange.old_addresses)
                else:
                    self._disjoint.add(
                        canon_addr,
                        canon_sizepass.size,
                        MemRange.old_addresses | MemRange.new_addresses,
                    )
                    if not needwarning and info.deadremoved > 0:
                        if not self._fd.isJumptableRecoveryOn():
                            if vn.isHeritageKnown():
                                continue
                            needwarning = True
                            self.bumpDeadcodeDelay(vn.getSpace())
                            warnvn = vn

            if needwarning and not info.warningissued:
                info.warningissued = True
                msg = "Heritage AFTER dead removal. Example location: "
                msg += warnvn.printRawNoMarkup()[0]
                if not warnvn.hasNoDescend():
                    warnop = next(warnvn.beginDescend())
                    msg += " : "
                    msg += warnop.getAddr().printRaw()
                self._fd.warningHeader(msg)

        self.placeMultiequals()
        self.rename()
        if reprocessStackCount > 0:
            self.reprocessFreeStores(stackSpace, freeStores)
        self.analyzeNewLoadGuards()
        self.handleNewLoadCopies()
        if self._pass == 0:
            splitmanage.splitAdditional()
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
