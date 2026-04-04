"""
Corresponds to: coreaction.hh / coreaction.cc
Core decompilation Action classes and universalAction pipeline wiring.
"""
from __future__ import annotations
from typing import Optional, TYPE_CHECKING
from ghidra.transform.action import Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase
from ghidra.types.datatype import TYPE_BOOL as _TYPE_BOOL

# Hot-path Varnode flag constants
_VN_STOP_UP = 0x800   # Varnode.stop_uppropagation (addlflags)
_VN_ANNOT   = 0x04    # Varnode.annotation (flags)
_VN_TYPELOCK = 0x08000000  # Varnode.typelock (highflags — checked via isTypeLock)

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# ---------------------------------------------------------------------------
# _PropState: helper for ActionInferTypes._propagateOneType.
# Defined at module level so the class body is only executed once, not 15K×.
# ---------------------------------------------------------------------------
_VN_WRITTEN_PS = 0x10  # Varnode.written (for _PropState)
_VN_MARK_PS   = 0x01  # Varnode.mark (for _propagateOneType)

class _PropState:
    __slots__ = ('vn', 'desc_iter', 'op', 'slot', 'inslot')
    def __init__(self, v):
        self.vn = v
        self.desc_iter = iter(v._descend)
        self.op = None
        self.slot = 0
        self.inslot = 0
        self._advance_op()
    def _advance_op(self):
        try:
            self.op = next(self.desc_iter)
            if self.op._output is not None:
                self.slot = -1
            else:
                self.slot = 0
            vn = self.vn
            inrefs = self.op._inrefs
            for i, ref in enumerate(inrefs):
                if ref is vn:
                    self.inslot = i
                    break
            else:
                self.inslot = len(inrefs)
        except StopIteration:
            vn = self.vn
            defop = vn._def if (vn._flags & _VN_WRITTEN_PS) else None
            if self.inslot != -1 and defop is not None:
                self.op = defop
                self.inslot = -1
                self.slot = 0
            else:
                self.op = None
    def valid(self):
        return self.op is not None
    def step(self):
        self.slot += 1
        if self.slot < len(self.op._inrefs):
            return
        self._advance_op()


class _StackEqn:
    __slots__ = ("var1", "var2", "rhs")

    def __init__(self, var1: int, var2: int, rhs: int):
        self.var1 = var1
        self.var2 = var2
        self.rhs = rhs


class _StackSolver:
    """Recover stack-pointer deltas across calls.

    Python port of the private native StackSolver helper in coreaction.cc.
    """

    __slots__ = ("eqs", "guess", "vnlist", "companion", "spacebase", "soln",
                 "missedvariables", "_eqs_by_var")

    _UNKNOWN = 65535

    def __init__(self):
        self.eqs = []
        self.guess = []
        self.vnlist = []
        self.companion = []
        self.spacebase = None
        self.soln = []
        self.missedvariables = 0
        self._eqs_by_var = {}

    def getNumVariables(self) -> int:
        return len(self.vnlist)

    def getVariable(self, i: int):
        return self.vnlist[i]

    def getCompanion(self, i: int) -> int:
        return self.companion[i]

    def getSolution(self, i: int) -> int:
        return self.soln[i]

    def propagate(self, varnum: int, val: int) -> None:
        if self.soln[varnum] != self._UNKNOWN:
            return
        self.soln[varnum] = val
        workstack = [varnum]
        while workstack:
            cur = workstack.pop()
            for eqn in self._eqs_by_var.get(cur, ()):
                if self.soln[eqn.var2] != self._UNKNOWN:
                    continue
                self.soln[eqn.var2] = self.soln[cur] - eqn.rhs
                workstack.append(eqn.var2)

    def duplicate(self) -> None:
        size = len(self.eqs)
        for i in range(size):
            eqn = self.eqs[i]
            self.eqs.append(_StackEqn(eqn.var2, eqn.var1, -eqn.rhs))
        self.eqs.sort(key=lambda eqn: eqn.var1)
        self._eqs_by_var = {}
        for eqn in self.eqs:
            self._eqs_by_var.setdefault(eqn.var1, []).append(eqn)

    def solve(self) -> None:
        size = len(self.guess)
        self.soln = [self._UNKNOWN] * len(self.vnlist)
        self.duplicate()
        self.propagate(0, 0)
        lastcount = size + 2
        while True:
            count = 0
            for eqn in self.guess:
                var1 = eqn.var1
                var2 = eqn.var2
                if self.soln[var1] != self._UNKNOWN and self.soln[var2] == self._UNKNOWN:
                    self.propagate(var2, self.soln[var1] - eqn.rhs)
                elif self.soln[var1] == self._UNKNOWN and self.soln[var2] != self._UNKNOWN:
                    self.propagate(var1, self.soln[var2] + eqn.rhs)
                elif self.soln[var1] == self._UNKNOWN and self.soln[var2] == self._UNKNOWN:
                    count += 1
            if count == 0 or count == lastcount:
                break
            lastcount = count

    def build(self, data, id_spc, spcbase: int) -> None:
        from ghidra.core.address import Address
        from ghidra.core.opcodes import OpCode
        from ghidra.core.space import IPTR_IOP
        from ghidra.fspec.fspec import ProtoModel

        spacebasedata = id_spc.getSpacebase(spcbase)
        self.spacebase = Address(spacebasedata.space, spacebasedata.offset)

        vnlist = []
        for vn in sorted(list(data._vbank.beginLoc())):
            if vn.getSize() != spacebasedata.size:
                continue
            if vn.getAddr() != self.spacebase:
                continue
            if vn.isFree():
                break
            vnlist.append(vn)

        self.vnlist = vnlist
        self.companion = [-1] * len(vnlist)
        self.missedvariables = 0
        if not self.vnlist:
            return
        if not self.vnlist[0].isInput():
            raise RuntimeError("Input value of stackpointer is not used")

        index_map = {id(vn): idx for idx, vn in enumerate(self.vnlist)}

        for i in range(1, len(self.vnlist)):
            vn = self.vnlist[i]
            op = vn.getDef()
            if op is None:
                self.missedvariables += 1
                continue

            if op.code() == OpCode.CPUI_INT_ADD:
                othervn = op.getIn(0)
                constvn = op.getIn(1)
                if othervn.isConstant():
                    constvn = othervn
                    othervn = op.getIn(1)
                if not constvn.isConstant() or othervn.getAddr() != self.spacebase:
                    self.missedvariables += 1
                    continue
                other_index = index_map.get(id(othervn))
                if other_index is None:
                    self.missedvariables += 1
                    continue
                self.eqs.append(_StackEqn(i, other_index, constvn.getOffset()))
            elif op.code() == OpCode.CPUI_COPY:
                othervn = op.getIn(0)
                if othervn.getAddr() != self.spacebase:
                    self.missedvariables += 1
                    continue
                other_index = index_map.get(id(othervn))
                if other_index is None:
                    self.missedvariables += 1
                    continue
                self.eqs.append(_StackEqn(i, other_index, 0))
            elif op.code() == OpCode.CPUI_INDIRECT:
                othervn = op.getIn(0)
                if othervn.getAddr() != self.spacebase:
                    self.missedvariables += 1
                    continue
                other_index = index_map.get(id(othervn))
                if other_index is None:
                    self.missedvariables += 1
                    continue
                self.companion[i] = other_index
                iopvn = op.getIn(1)
                if iopvn.getSpace() is not None and iopvn.getSpace().getType() == IPTR_IOP:
                    iop = data.getOpFromConst(iopvn.getAddr()) if hasattr(data, 'getOpFromConst') else getattr(iopvn, '_iop_ref', None)
                    fc = data.getCallSpecs(iop) if iop is not None and hasattr(data, 'getCallSpecs') else None
                    if fc is not None and fc.getExtraPop() != ProtoModel.extrapop_unknown:
                        self.eqs.append(_StackEqn(i, other_index, fc.getExtraPop()))
                        continue
                self.guess.append(_StackEqn(i, other_index, 4))
            elif op.code() == OpCode.CPUI_MULTIEQUAL:
                for j in range(op.numInput()):
                    othervn = op.getIn(j)
                    if othervn.getAddr() != self.spacebase:
                        self.missedvariables += 1
                        continue
                    other_index = index_map.get(id(othervn))
                    if other_index is None:
                        self.missedvariables += 1
                        continue
                    self.eqs.append(_StackEqn(i, other_index, 0))
            elif op.code() == OpCode.CPUI_INT_AND:
                othervn = op.getIn(0)
                constvn = op.getIn(1)
                if othervn.isConstant():
                    constvn = othervn
                    othervn = op.getIn(1)
                if not constvn.isConstant() or othervn.getAddr() != self.spacebase:
                    self.missedvariables += 1
                    continue
                other_index = index_map.get(id(othervn))
                if other_index is None:
                    self.missedvariables += 1
                    continue
                self.eqs.append(_StackEqn(i, other_index, 0))
            else:
                self.missedvariables += 1


# --- Simple Action stubs that delegate to Funcdata methods ---

class ActionStart(Action):
    def __init__(self, g): super().__init__(0, "start", g)
    def clone(self, gl):
        return ActionStart(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        if not data.isProcStarted():
            data.startProcessing()
        return 0

class ActionStop(Action):
    def __init__(self, g): super().__init__(0, "stop", g)
    def clone(self, gl):
        return ActionStop(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.stopProcessing(); return 0

class ActionStartCleanUp(Action):
    def __init__(self, g): super().__init__(0, "startcleanup", g)
    def clone(self, gl):
        return ActionStartCleanUp(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.startCleanUp(); return 0

class ActionStartTypes(Action):
    def __init__(self, g): super().__init__(0, "starttypes", g)
    def clone(self, gl):
        return ActionStartTypes(self._basegroup) if gl.contains(self._basegroup) else None
    def reset(self, data): data.setTypeRecovery(True)
    def apply(self, data):
        if data.startTypeRecovery(): self._count += 1
        return 0

class ActionHeritage(Action):
    def __init__(self, g): super().__init__(0, "heritage", g)
    def clone(self, gl):
        return ActionHeritage(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.opHeritage(); return 0

class ActionNonzeroMask(Action):
    def __init__(self, g): super().__init__(0, "nonzeromask", g)
    def clone(self, gl):
        return ActionNonzeroMask(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.calcNZMask(); return 0

class ActionConstbase(Action):
    """Inject tracked-context register constants as COPY ops at function entry."""
    def __init__(self, g): super().__init__(0, "constbase", g)
    def clone(self, gl):
        return ActionConstbase(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        if graph.getSize() == 0:
            return 0
        bb = graph.getBlock(0)
        glb = data.getArch()
        if glb is None:
            return 0
        ctx = getattr(glb, 'context', None)
        if ctx is None:
            return 0
        trackset = ctx.getTrackedSet(data.getAddress())
        if trackset is None:
            return 0
        for tracked in trackset:
            from ghidra.core.address import Address
            addr = Address(tracked.loc.space, tracked.loc.offset)
            op = data.newOp(1, bb.getStart())
            data.newVarnodeOut(tracked.loc.size, addr, op)
            vnin = data.newConstant(tracked.loc.size, tracked.val)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, vnin, 0)
            data.opInsertBegin(op, bb)
        return 0

class ActionSpacebase(Action):
    """Mark Varnode objects that hold stack-pointer values as spacebase."""
    def __init__(self, g): super().__init__(0, "spacebase", g)
    def clone(self, gl):
        return ActionSpacebase(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.spacebase()
        return 0

class ActionUnreachable(Action):
    """Remove unreachable blocks."""
    def __init__(self, g): super().__init__(0, "unreachable", g)
    def clone(self, gl):
        return ActionUnreachable(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        if data.removeUnreachableBlocks(True, False):
            self._count += 1
        return 0

from ghidra.transform.deadcode import ActionDeadCode  # Real implementation

class ActionDoNothing(Action):
    """Remove blocks that do nothing."""
    def __init__(self, g): super().__init__(Action.rule_repeatapply, "donothing", g)
    def clone(self, gl):
        return ActionDoNothing(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if hasattr(bb, 'isDoNothing') and bb.isDoNothing():
                if bb.sizeOut() == 1 and bb.getOut(0) is bb:
                    if not hasattr(bb, '_donothingloop'):
                        bb._donothingloop = True
                        data.warning("Do nothing block with infinite loop", bb.getStart())
                elif bb.unblockedMulti(0):
                    data.removeDoNothingBlock(bb)
                    self._count += 1
                    return 0
        return 0

class ActionRedundBranch(Action):
    """Remove redundant branches: duplicate edges between same input and output block."""
    def __init__(self, g): super().__init__(0, "redundbranch", g)
    def clone(self, gl):
        return ActionRedundBranch(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getBasicBlocks()
        i = 0
        while i < graph.getSize():
            bb = graph.getBlock(i)
            if bb.sizeOut() == 0:
                i += 1
                continue
            bl = bb.getOut(0)
            if bb.sizeOut() == 1:
                if bl.sizeIn() == 1 and not bl.isEntryPoint():
                    data.spliceBlockBasic(bb)
                    self._count += 1
                    i = 0
                    continue
                i += 1
                continue
            allsame = all(bb.getOut(j) is bl for j in range(1, bb.sizeOut()))
            if allsame:
                data.removeBranch(bb, 1)
                self._count += 1
            i += 1
        return 0

class ActionDeterminedBranch(Action):
    """Remove conditional branches if the condition is constant."""
    def __init__(self, g): super().__init__(0, "determinedbranch", g)
    def clone(self, gl):
        return ActionDeterminedBranch(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            cbranch = bb.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            if not cbranch.getIn(1).isConstant():
                continue
            val = cbranch.getIn(1).getOffset()
            num = 0 if ((val != 0) != cbranch.isBooleanFlip()) else 1
            data.removeBranch(bb, num)
            self._count += 1
        return 0

class ActionVarnodeProps(Action):
    """Transform based on Varnode properties (readonly, volatile, unconsumed)."""
    def __init__(self, g): super().__init__(0, "varnodeprops", g)
    def clone(self, gl):
        return ActionVarnodeProps(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.address import calc_mask
        from ghidra.core.opcodes import OpCode
        for vn in list(data._vbank.beginLoc()):
            if vn.isAnnotation(): continue
            sz = vn.getSize()
            if sz > 8: continue
            nzm = vn.getNZMask()
            cons = vn.getConsume()
            if (nzm & cons) == 0 and not vn.isConstant():
                if vn.isWritten():
                    defop = vn.getDef()
                    if defop.code() == OpCode.CPUI_COPY:
                        inv = defop.getIn(0)
                        if inv.isConstant() and inv.getOffset() == 0:
                            continue
                if not vn.hasNoDescend():
                    for desc in list(vn.getDescendants()):
                        slot = desc.getSlot(vn)
                        data.opSetInput(desc, data.newConstant(sz, 0), slot)
                    self._count += 1
        return 0

class ActionDirectWrite(Action):
    """Mark Varnodes built out of legal parameters with directwrite attribute."""
    def __init__(self, g, prop=True):
        super().__init__(0, "directwrite", g)
        self._propagateIndirect = prop
    def clone(self, gl):
        return ActionDirectWrite(self._basegroup, self._propagateIndirect) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # All these flags live in Varnode._flags
        _VN_INPUT    = 0x08     # Varnode.input
        _VN_WRITTEN  = 0x10     # Varnode.written
        _VN_CONST    = 0x02     # Varnode.constant
        _VN_PERSIST  = 0x4000   # Varnode.persist
        _VN_SPBASE   = 0x20000  # Varnode.spacebase
        _VN_DWRITE   = 0x80000  # Varnode.directwrite
        _VN_INDCR    = 0x400000  # Varnode.indirect_creation (for isIndirectZero)
        _OP_MARKER   = 0x40     # PcodeOp.marker
        _OPC_COPY    = 1; _OPC_PIECE = 62; _OPC_SUBPIECE = 63
        _OPC_INDIRECT = 61      # CPUI_INDIRECT
        prop = self._propagateIndirect
        worklist = []
        proto = data.getFuncProto() if hasattr(data, 'getFuncProto') else None
        for vn in list(data._vbank.beginLoc()):
            vn_flags = vn._flags
            vn._flags = vn_flags & ~_VN_DWRITE  # clearDirectWrite
            if vn_flags & _VN_INPUT:
                if vn_flags & (_VN_PERSIST | _VN_SPBASE):
                    vn._flags |= _VN_DWRITE
                    worklist.append(vn)
                elif proto is not None and hasattr(proto, 'possibleInputParam'):
                    if proto.possibleInputParam(vn.getAddr(), vn.getSize()):
                        vn._flags |= _VN_DWRITE
                        worklist.append(vn)
            elif vn_flags & _VN_WRITTEN:
                op = vn._def
                if not (op._flags & _OP_MARKER):
                    if vn_flags & _VN_PERSIST:
                        vn._flags |= _VN_DWRITE
                        worklist.append(vn)
                    elif op._opcode_enum == _OPC_COPY:
                        if hasattr(vn, 'isStackStore') and vn.isStackStore():
                            invn = op._inrefs[0] if op._inrefs else None
                            if invn is not None and invn.isWritten():
                                curop = invn._def
                                if curop is not None and curop._opcode_enum == _OPC_COPY:
                                    invn = curop._inrefs[0] if curop._inrefs else invn
                            if invn is not None and invn.isWritten():
                                defop = invn._def
                                if defop is not None and (defop._flags & _OP_MARKER):
                                    vn._flags |= _VN_DWRITE
                                    worklist.append(vn)
                    elif op._opcode_enum not in (_OPC_COPY, _OPC_PIECE, _OPC_SUBPIECE):
                        vn._flags |= _VN_DWRITE
                        worklist.append(vn)
                elif not prop and op._opcode_enum == _OPC_INDIRECT:
                    outvn = op._output
                    _a1 = op._inrefs[0]._loc; _a2 = outvn._loc
                    if _a1.base is not _a2.base or _a1.offset != _a2.offset:
                        vn._flags |= _VN_DWRITE
                    elif outvn._flags & _VN_PERSIST:
                        vn._flags |= _VN_DWRITE
            elif vn_flags & _VN_CONST:
                # isIndirectZero = (indirect_creation | constant) both set
                if not (vn_flags & _VN_INDCR):
                    vn._flags |= _VN_DWRITE
                    worklist.append(vn)
        while worklist:
            vn = worklist.pop()
            for op in vn._descend:
                if op._output is None:  # isAssignment
                    continue
                dvn = op._output
                if dvn is None:
                    continue
                dvn_flags = dvn._flags
                if not (dvn_flags & _VN_DWRITE):
                    dvn._flags = dvn_flags | _VN_DWRITE
                    if prop or op._opcode_enum != _OPC_INDIRECT or op.isIndirectStore():
                        worklist.append(dvn)
        return 0

class ActionForceGoto(Action):
    """Apply any overridden forced gotos.

    C++ ref: ``ActionForceGoto::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "forcegoto", g)
    def clone(self, gl):
        return ActionForceGoto(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        override = data.getOverride() if hasattr(data, 'getOverride') else None
        if override is not None and hasattr(override, 'applyForceGoto'):
            override.applyForceGoto(data)
        return 0

class ActionSegmentize(Action):
    """Convert user-defined segment p-code ops into internal CPUI_SEGMENTOP.

    C++ ref: ``ActionSegmentize::apply`` in coreaction.cc
    """
    def __init__(self, g):
        super().__init__(0, "segmentize", g)
        self._localcount: int = 0
    def clone(self, gl):
        return ActionSegmentize(self._basegroup) if gl.contains(self._basegroup) else None
    def reset(self, data):
        super().reset(data)
        self._localcount = 0
    def apply(self, data):
        arch = data.getArch()
        userops = getattr(arch, 'userops', None)
        if userops is None:
            return 0
        numops = userops.numSegmentOps() if hasattr(userops, 'numSegmentOps') else 0
        if numops == 0:
            return 0
        if self._localcount > 0:
            return 0
        self._localcount = 1
        from ghidra.core.opcodes import OpCode
        for i in range(numops):
            segdef = userops.getSegmentOp(i)
            if segdef is None:
                continue
            spc = segdef.getSpace()
            uindex = segdef.getIndex()
            for segroot in list(data.beginOp(OpCode.CPUI_CALLOTHER)):
                if segroot.isDead():
                    continue
                if segroot.getIn(0).getOffset() != uindex:
                    continue
                bindlist = [None, None]
                if hasattr(segdef, 'unify') and not segdef.unify(data, segroot, bindlist):
                    raise RuntimeError(f"Segment op in wrong form at {segroot.getAddr()}")
                if hasattr(segdef, 'getNumVariableTerms') and segdef.getNumVariableTerms() == 1:
                    bindlist[0] = data.newConstant(4, 0)
                data.opSetOpcode(segroot, OpCode.CPUI_SEGMENTOP)
                data.opSetInput(segroot, data.newVarnodeSpace(spc), 0)
                data.opSetInput(segroot, bindlist[0], 1)
                data.opSetInput(segroot, bindlist[1], 2)
                for j in range(segroot.numInput() - 1, 2, -1):
                    data.opRemoveInput(segroot, j)
                self._count += 1
        return 0

class ActionInternalStorage(Action):
    """Mark STOREs fed by internal storage as unmapped when appropriate.

    C++ ref: ``ActionInternalStorage::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "internalstorage", g)
    def clone(self, gl):
        return ActionInternalStorage(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode

        proto = data.getFuncProto() if hasattr(data, "getFuncProto") else None
        if proto is None or not hasattr(proto, "internalBegin"):
            return 0

        vbank = getattr(data, "_vbank", None)
        if vbank is None:
            return 0

        for storage in proto.internalBegin():
            if storage is None:
                continue
            if hasattr(storage, "getAddr"):
                addr = storage.getAddr()
            else:
                space = getattr(storage, "space", None)
                offset = getattr(storage, "offset", 0)
                from ghidra.core.address import Address
                addr = Address(space, offset)
            size = storage.size if hasattr(storage, "size") else getattr(storage, "getSize", lambda: 0)()
            if size <= 0 or addr is None:
                continue

            if hasattr(vbank, "beginLocSize"):
                varnodes = list(vbank.beginLocSize(size, addr))
            elif hasattr(vbank, "findLoc"):
                varnodes = list(vbank.findLoc(addr, size))
            else:
                varnodes = [
                    vn for vn in vbank.beginLoc()
                    if vn.getSize() == size and vn.getAddr() == addr
                ]

            for vn in varnodes:
                for op in list(vn.getDescendants()):
                    if op.code() != OpCode.CPUI_STORE:
                        continue
                    if vn.isEventualConstant(3, 0):
                        op.setStoreUnmapped()
        return 0

class ActionMultiCse(Action):
    """Eliminate redundant MULTIEQUAL ops using native matching semantics."""
    def __init__(self, g): super().__init__(0, "multicse", g)
    def clone(self, gl):
        return ActionMultiCse(self._basegroup) if gl.contains(self._basegroup) else None
    @staticmethod
    def _unwrapCopy(vn):
        from ghidra.core.opcodes import OpCode

        if vn is not None and vn.isWritten():
            defop = vn.getDef()
            if defop is not None and defop.code() == OpCode.CPUI_COPY:
                return defop.getIn(0)
        return vn

    @staticmethod
    def preferredOutput(out1, out2):
        from ghidra.core.opcodes import OpCode
        from ghidra.core.space import IPTR_INTERNAL

        for op in out1.getDescendants():
            if op.code() == OpCode.CPUI_RETURN:
                return False
        for op in out2.getDescendants():
            if op.code() == OpCode.CPUI_RETURN:
                return True
        if not out1.isAddrTied():
            if out2.isAddrTied():
                return True
            spc1 = out1.getSpace()
            spc2 = out2.getSpace()
            if spc1 is not None and spc1.getType() == IPTR_INTERNAL:
                if spc2 is not None and spc2.getType() != IPTR_INTERNAL:
                    return True
        return False

    @staticmethod
    def findMatch(bl, target, in_vn):
        from ghidra.core.expression import functionalEqualityLevel

        for op in bl.beginOp():
            if op is target:
                break
            numinput = op.numInput()
            for i in range(numinput):
                vn = ActionMultiCse._unwrapCopy(op.getIn(i))
                if vn is in_vn:
                    break
            else:
                continue

            for j in range(numinput):
                in1 = ActionMultiCse._unwrapCopy(op.getIn(j))
                in2 = ActionMultiCse._unwrapCopy(target.getIn(j))
                if in1 is in2:
                    continue
                buf1 = [None, None]
                buf2 = [None, None]
                if functionalEqualityLevel(in1, in2, buf1, buf2) != 0:
                    break
            else:
                return op
        return None

    def processBlock(self, data, bl):
        from ghidra.core.opcodes import OpCode

        vnlist = []
        targetop = None
        pairop = None
        for op in bl.beginOp():
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                continue
            if opc != OpCode.CPUI_MULTIEQUAL:
                break

            vnpos = len(vnlist)
            for i in range(op.numInput()):
                vn = self._unwrapCopy(op.getIn(i))
                vnlist.append(vn)
                if vn.isMark():
                    pairop = self.findMatch(bl, op, vn)
                    if pairop is not None:
                        targetop = op
                        break
            if targetop is not None:
                break
            for i in range(vnpos, len(vnlist)):
                vnlist[i].setMark()

        for vn in vnlist:
            vn.clearMark()

        if targetop is None:
            return False

        out1 = pairop.getOut()
        out2 = targetop.getOut()
        if self.preferredOutput(out1, out2):
            data.totalReplace(out1, out2)
            data.opDestroy(pairop)
        else:
            data.totalReplace(out2, out1)
            data.opDestroy(targetop)
        self._count += 1
        return True

    def apply(self, data):
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            while self.processBlock(data, bl):
                pass
        return 0

class ActionShadowVar(Action):
    """Detect shadow MULTIEQUAL ops that share input[0] and are redundant."""
    def __init__(self, g): super().__init__(0, "shadowvar", g)
    def clone(self, gl):
        return ActionShadowVar(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        oplist = []
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            vnlist = []
            ops = list(bl.getOps()) if hasattr(bl, 'getOps') else []
            for op in ops:
                if op.code() != OpCode.CPUI_MULTIEQUAL:
                    continue
                vn = op.getIn(0)
                if vn.isMark():
                    oplist.append(op)
                else:
                    vn.setMark()
                    vnlist.append(vn)
            for vn in vnlist:
                vn.clearMark()
        for op in oplist:
            prev = op.previousOp() if hasattr(op, 'previousOp') else None
            while prev is not None:
                if prev.code() != OpCode.CPUI_MULTIEQUAL:
                    prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
                    continue
                if prev.numInput() != op.numInput():
                    prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
                    continue
                match = all(op.getIn(k) is prev.getIn(k) for k in range(op.numInput()))
                if match:
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                    data.opSetAllInput(op, [prev.getOut()])
                    self._count += 1
                    break
                prev = prev.previousOp() if hasattr(prev, 'previousOp') else None
        return 0

class ActionDeindirect(Action):
    """Resolve indirect calls to direct calls where possible.

    C++ ref: ``ActionDeindirect::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "deindirect", g)
    def clone(self, gl):
        return ActionDeindirect(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.types.datatype import TYPE_PTR, TYPE_CODE
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            op = fc.getOp()
            if op.code() != OpCode.CPUI_CALLIND:
                continue
            vn = op.getIn(0)
            while vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
                vn = vn.getDef().getIn(0)
            # Check for external reference
            if vn.isPersist() and (hasattr(vn, 'isExternalRef') and vn.isExternalRef()):
                localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
                if localmap is not None and hasattr(localmap, 'getParent'):
                    parent = localmap.getParent()
                    if parent is not None and hasattr(parent, 'queryExternalRefFunction'):
                        newfd = parent.queryExternalRefFunction(vn.getAddr())
                        if newfd is not None:
                            if hasattr(fc, 'deindirect'):
                                fc.deindirect(data, newfd)
                            self._count += 1
                            continue
            elif vn.isConstant():
                # Convert constant to byte address in calling function's space
                sp = data.getAddress().getSpace() if hasattr(data, 'getAddress') else None
                if sp is not None:
                    from ghidra.core.space import AddrSpace
                    offset = vn.getOffset()
                    if hasattr(AddrSpace, 'addressToByte'):
                        offset = AddrSpace.addressToByte(offset, sp.getWordSize())
                    arch = data.getArch()
                    if arch is not None and hasattr(arch, 'funcptr_align'):
                        align = arch.funcptr_align
                        if align != 0:
                            offset = (offset >> align) << align
                    localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
                    if localmap is not None and hasattr(localmap, 'getParent'):
                        parent = localmap.getParent()
                        if parent is not None and hasattr(parent, 'queryFunction'):
                            from ghidra.core.address import Address
                            codeaddr = Address(sp, offset)
                            newfd = parent.queryFunction(codeaddr)
                            if newfd is not None:
                                if hasattr(fc, 'deindirect'):
                                    fc.deindirect(data, newfd)
                                self._count += 1
                                continue
            # Check for function pointer type
            if hasattr(data, 'hasTypeRecoveryStarted') and data.hasTypeRecoveryStarted():
                ct = op.getIn(0).getTypeReadFacing(op) if hasattr(op.getIn(0), 'getTypeReadFacing') else None
                if ct is not None and hasattr(ct, 'getMetatype') and ct.getMetatype() == TYPE_PTR:
                    ptrto = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
                    if ptrto is not None and hasattr(ptrto, 'getMetatype') and ptrto.getMetatype() == TYPE_CODE:
                        fp = ptrto.getPrototype() if hasattr(ptrto, 'getPrototype') else None
                        if fp is not None:
                            if not fc.isInputLocked():
                                if hasattr(fc, 'forceSet'):
                                    fc.forceSet(data, fp)
                                self._count += 1
        return 0

class ActionStackPtrFlow(Action):
    """Analyze stack-pointer flow and resolve unknown extra-pop values.

    C++ ref: ``ActionStackPtrFlow::apply`` in coreaction.cc
    """
    def __init__(self, g, ss=None):
        super().__init__(0, "stackptrflow", g)
        self._stackspace = ss
        self._analysis_finished = False
    def clone(self, gl):
        return ActionStackPtrFlow(self._basegroup, self._stackspace) if gl.contains(self._basegroup) else None
    # NOTE: No reset() override — C++ inherits Action::reset which does NOT
    # clear analysis_finished.  Clearing it here caused infinite re-analysis
    # on every mainloop repeat.

    @staticmethod
    def isStackRelative(spcbasein, vn):
        """Check if *vn* is the stack-pointer input or SP + constant.

        Returns (True, constval) if stack-relative, (False, 0) otherwise.
        C++ ref: ``ActionStackPtrFlow::isStackRelative``
        """
        if spcbasein is vn:
            return True, 0
        if not vn.isWritten():
            return False, 0
        from ghidra.core.opcodes import OpCode
        addop = vn.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD:
            return False, 0
        if addop.getIn(0) is not spcbasein:
            return False, 0
        constvn = addop.getIn(1)
        if not constvn.isConstant():
            return False, 0
        return True, constvn.getOffset()

    @staticmethod
    def adjustLoad(data, loadop, storeop):
        """Convert a LOAD to a COPY of the stored value.

        C++ ref: ``ActionStackPtrFlow::adjustLoad``
        """
        from ghidra.core.opcodes import OpCode
        vn = storeop.getIn(2)
        if vn.isConstant():
            vn = data.newConstant(vn.getSize(), vn.getOffset())
        elif vn.isFree():
            return False
        data.opRemoveInput(loadop, 1)
        data.opSetOpcode(loadop, OpCode.CPUI_COPY)
        data.opSetInput(loadop, vn, 0)
        return True

    @staticmethod
    def repair(data, id_spc, spcbasein, loadop, constz):
        """Find matching STORE for a LOAD and convert LOAD to COPY.

        Walks backwards from *loadop* through the basic block (and single-path
        predecessors) looking for a STORE to the same stack-relative address.

        C++ ref: ``ActionStackPtrFlow::repair``
        """
        from ghidra.core.opcodes import OpCode
        loadsize = loadop.getOut().getSize()
        curblock = loadop.getParent()
        oplist = list(curblock.getOpList())
        # Find loadop's index in the block
        load_idx = None
        for idx, op in enumerate(oplist):
            if op is loadop:
                load_idx = idx
                break
        if load_idx is None:
            return 0
        idx = load_idx - 1
        while True:
            if idx < 0:
                # Try to go to single predecessor
                if curblock.sizeIn() != 1:
                    return 0
                curblock = curblock.getIn(0)
                oplist = list(curblock.getOpList())
                idx = len(oplist) - 1
                continue
            curop = oplist[idx]
            idx -= 1
            if curop.isCall():
                return 0
            if curop.code() == OpCode.CPUI_STORE:
                ptrvn = curop.getIn(1)
                datavn = curop.getIn(2)
                ok, constnew = ActionStackPtrFlow.isStackRelative(spcbasein, ptrvn)
                if ok:
                    if constnew == constz and loadsize == datavn.getSize():
                        if ActionStackPtrFlow.adjustLoad(data, loadop, curop):
                            return 1
                        return 0
                    elif (constnew <= constz + (loadsize - 1)) and (constnew + (datavn.getSize() - 1) >= constz):
                        return 0
                else:
                    return 0
            else:
                outvn = curop.getOut()
                if outvn is not None:
                    if outvn.getSpace() is id_spc:
                        return 0
        return 0

    @staticmethod
    def checkClog(data, id_spc, spcbase):
        """Find stack-pointer clogs and repair them.

        A clog is a constant addition to the stack pointer where the constant
        is loaded from the stack itself (e.g. function epilogue restoring SP).

        C++ ref: ``ActionStackPtrFlow::checkClog``
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import Address, calc_mask
        if not hasattr(id_spc, 'numSpacebase') or id_spc.numSpacebase() == 0:
            return 0
        spacebasedata = id_spc.getSpacebase(spcbase)
        if spacebasedata is None:
            return 0
        sb_space = spacebasedata.space if hasattr(spacebasedata, 'space') else None
        sb_offset = spacebasedata.offset if hasattr(spacebasedata, 'offset') else 0
        sb_size = spacebasedata.size if hasattr(spacebasedata, 'size') else 4
        if sb_space is None:
            return 0
        spacebase_addr = Address(sb_space, sb_offset)

        # Find input varnode for the stack pointer
        spcbasein = None
        if hasattr(data, 'findVarnodeInput'):
            spcbasein = data.findVarnodeInput(sb_size, spacebase_addr)
        if spcbasein is None:
            return 0

        clogcount = 0
        # Iterate all varnodes at the stack pointer location
        candidates = []
        for vn in list(data._vbank.beginLoc()):
            if vn.getSpace() is not sb_space:
                continue
            if vn.getOffset() != sb_offset:
                continue
            if vn.getSize() != sb_size:
                continue
            if vn is spcbasein:
                continue
            if not vn.isWritten():
                continue
            candidates.append(vn)

        for outvn in candidates:
            addop = outvn.getDef()
            if addop.code() != OpCode.CPUI_INT_ADD:
                continue
            y = addop.getIn(1)
            if not y.isWritten():
                continue
            x = addop.getIn(0)
            ok, constx = ActionStackPtrFlow.isStackRelative(spcbasein, x)
            if not ok:
                x = y
                y = addop.getIn(0)
                ok, constx = ActionStackPtrFlow.isStackRelative(spcbasein, x)
                if not ok:
                    continue
            loadop = y.getDef()
            if loadop.code() == OpCode.CPUI_INT_MULT:
                constvn = loadop.getIn(1)
                if not constvn.isConstant():
                    continue
                if constvn.getOffset() != calc_mask(constvn.getSize()):
                    continue
                y = loadop.getIn(0)
                if not y.isWritten():
                    continue
                loadop = y.getDef()
            if loadop.code() != OpCode.CPUI_LOAD:
                continue
            ptrvn = loadop.getIn(1)
            ok2, constz = ActionStackPtrFlow.isStackRelative(spcbasein, ptrvn)
            if not ok2:
                continue
            clogcount += ActionStackPtrFlow.repair(data, id_spc, spcbasein, loadop, constz)
        return clogcount

    @staticmethod
    def analyzeExtraPop(data, stackspace, spcbase):
        """Analyze extra pop for call sites using a stack equation solver.

        C++ ref: ``ActionStackPtrFlow::analyzeExtraPop``
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import calc_mask
        from ghidra.core.space import IPTR_IOP
        from ghidra.fspec.fspec import ProtoModel

        arch = data.getArch() if hasattr(data, 'getArch') else None
        if arch is None:
            return
        myfp = getattr(arch, 'evalfp_called', None)
        if myfp is None:
            myfp = getattr(arch, 'defaultfp', None)
        if myfp is None:
            return
        if hasattr(myfp, 'getExtraPop') and myfp.getExtraPop() != ProtoModel.extrapop_unknown:
            return

        solver = _StackSolver()
        try:
            solver.build(data, stackspace, spcbase)
        except Exception as err:
            if hasattr(data, 'warningHeader'):
                data.warningHeader(f"Stack frame is not setup normally: {err}")
            return
        if solver.getNumVariables() == 0:
            return
        solver.solve()

        invn = solver.getVariable(0)
        warningprinted = False
        for i in range(1, solver.getNumVariables()):
            vn = solver.getVariable(i)
            soln = solver.getSolution(i)
            if soln == _StackSolver._UNKNOWN:
                if not warningprinted and hasattr(data, 'warningHeader'):
                    data.warningHeader(f"Unable to track spacebase fully for {stackspace.getName()}")
                    warningprinted = True
                continue
            op = vn.getDef()
            if op is None:
                continue
            if op.code() == OpCode.CPUI_INDIRECT:
                iopvn = op.getIn(1)
                if iopvn.getSpace() is not None and iopvn.getSpace().getType() == IPTR_IOP:
                    iop = data.getOpFromConst(iopvn.getAddr()) if hasattr(data, 'getOpFromConst') else getattr(iopvn, '_iop_ref', None)
                    fc = data.getCallSpecs(iop) if iop is not None and hasattr(data, 'getCallSpecs') else None
                    if fc is not None:
                        soln2 = 0
                        comp = solver.getCompanion(i)
                        if comp >= 0:
                            compsoln = solver.getSolution(comp)
                            if compsoln != _StackSolver._UNKNOWN:
                                soln2 = compsoln
                        fc.setEffectiveExtraPop(soln - soln2)
            sz = invn.getSize()
            data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
            data.opSetAllInput(op, [invn, data.newConstant(sz, soln & calc_mask(sz))])

    def apply(self, data):
        if self._analysis_finished:
            return 0
        if self._stackspace is None:
            self._analysis_finished = True
            return 0
        numchange = ActionStackPtrFlow.checkClog(data, self._stackspace, 0)
        if numchange > 0:
            self._count += 1
        if numchange == 0:
            ActionStackPtrFlow.analyzeExtraPop(data, self._stackspace, 0)
            self._analysis_finished = True
        return 0

class ActionLaneDivide(Action):
    """Divide laned registers (SIMD) into individual lane-sized variables."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "lanedivide", g)
    def clone(self, gl):
        return ActionLaneDivide(self._basegroup) if gl.contains(self._basegroup) else None
    @staticmethod
    def collectLaneSizes(vn, allowedLanes, checkLanes):
        from ghidra.core.opcodes import OpCode

        descendants = list(vn.getDescendants())
        step = 0
        idx = 0
        if not descendants:
            step = 1
        while step < 2:
            if step == 0:
                op = descendants[idx]
                idx += 1
                if idx >= len(descendants):
                    step = 1
                if op.code() != OpCode.CPUI_SUBPIECE:
                    continue
                curSize = op.getOut().getSize()
            else:
                step = 2
                if not vn.isWritten():
                    continue
                op = vn.getDef()
                if op.code() != OpCode.CPUI_PIECE:
                    continue
                curSize = op.getIn(0).getSize()
                tmpSize = op.getIn(1).getSize()
                if tmpSize < curSize:
                    curSize = tmpSize
            if allowedLanes.allowedLane(curSize):
                checkLanes.addLaneSize(curSize)

    def processVarnode(self, data, vn, lanedRegister, mode):
        from ghidra.analysis.subflow import LaneDivide
        from ghidra.transform.transform import LaneDescription, LanedRegister

        checkLanes = LanedRegister()
        allowDowncast = mode > 0
        if mode < 2:
            self.collectLaneSizes(vn, lanedRegister, checkLanes)
        else:
            arch = data.getArch()
            types = arch.types if arch is not None and hasattr(arch, 'types') else None
            defaultSize = types.getSizeOfPointer() if types is not None and hasattr(types, 'getSizeOfPointer') else 8
            if defaultSize != 4:
                defaultSize = 8
            checkLanes.addLaneSize(defaultSize)

        for curSize in checkLanes:
            description = LaneDescription(lanedRegister.getWholeSize(), curSize)
            laneDivide = LaneDivide(data, vn, description, allowDowncast)
            if laneDivide.doTrace():
                laneDivide.apply()
                self._count += 1
                return True
        return False

    def apply(self, data):
        data.setLanedRegGenerated()
        for mode in range(3):
            allStorageProcessed = True
            for vdata, lanedReg in data.beginLaneAccess():
                addr = vdata.getAddr()
                sz = vdata.size
                viter = list(data._vbank.beginLocSize(sz, addr))
                idx = 0
                allVarnodesProcessed = True
                while idx < len(viter):
                    vn = viter[idx]
                    if vn.hasNoDescend():
                        idx += 1
                        continue
                    if self.processVarnode(data, vn, lanedReg, mode):
                        viter = list(data._vbank.beginLocSize(sz, addr))
                        idx = 0
                        allVarnodesProcessed = True
                    else:
                        idx += 1
                        allVarnodesProcessed = False
                if not allVarnodesProcessed:
                    allStorageProcessed = False
            if allStorageProcessed:
                break
        data.clearLanedAccessMap()
        return 0

class ActionConstantPtr(Action):
    """Identify constant values that are likely pointers and mark them."""
    def __init__(self, g): super().__init__(0, "constantptr", g)
    def clone(self, gl):
        return ActionConstantPtr(self._basegroup) if gl.contains(self._basegroup) else None
    _OPC_STORE   = 3   # OpCode.CPUI_STORE
    _OPC_LOAD    = 2   # OpCode.CPUI_LOAD
    _OPC_CALLIND = 8   # OpCode.CPUI_CALLIND
    _VN_CONST    = 0x02  # Varnode.constant
    _PTRCHK      = 0x10  # addlflags ptrcheck bit

    def apply(self, data):
        glb = data.getArch()
        if glb is None:
            return 0
        _OPC_STORE = self._OPC_STORE; _OPC_LOAD = self._OPC_LOAD
        _OPC_CALLIND = self._OPC_CALLIND
        _VN_CONST = self._VN_CONST; _PTRCHK = self._PTRCHK
        for op in list(data._obank.beginAlive()):
            opc = op._opcode_enum
            for slot, vn in enumerate(op._inrefs):
                if vn is None or not (vn._flags & _VN_CONST):
                    continue
                if vn._size < 4:
                    continue
                if vn._addlflags & _PTRCHK:
                    continue  # ptrcheck already set
                if opc in (_OPC_STORE, _OPC_LOAD):
                    if slot == 1:  # pointer operand
                        vn._addlflags |= _PTRCHK
                elif opc == _OPC_CALLIND and slot == 0:
                    vn._addlflags |= _PTRCHK
        return 0

class ActionConditionalConst(Action):
    """Propagate constants down conditional branches where the condition implies a known value."""
    def __init__(self, g): super().__init__(0, "condconst", g)
    def clone(self, gl):
        return ActionConditionalConst(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bl = graph.getBlock(i)
            cbranch = bl.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            boolVn = cbranch.getIn(1)
            if boolVn.loneDescend() is not None:
                continue  # Only read once (by the CBRANCH itself)
            # The boolean is read elsewhere: propagate bool=0 / bool=1
            # down the false/true branches respectively
            flipEdge = cbranch.isBooleanFlip()
            falseVal = 1 if flipEdge else 0
            trueVal = 0 if flipEdge else 1
            # For each descendant of boolVn that is dominated by one branch,
            # replace boolVn with the appropriate constant
            for desc in list(boolVn.getDescendants()):
                if desc is cbranch:
                    continue
                parent = desc.getParent()
                if parent is None:
                    continue
                # Check if desc's block is dominated by false or true out
                falseOut = bl.getFalseOut()
                trueOut = bl.getTrueOut()
                if falseOut is not None and falseOut.dominates(parent):
                    slot = desc.getSlot(boolVn)
                    data.opSetInput(desc, data.newConstant(boolVn.getSize(), falseVal), slot)
                    self._count += 1
                elif trueOut is not None and trueOut.dominates(parent):
                    slot = desc.getSlot(boolVn)
                    data.opSetInput(desc, data.newConstant(boolVn.getSize(), trueVal), slot)
                    self._count += 1
        return 0

class ActionInferTypes(Action):
    """Infer and propagate data-types through the data-flow graph.

    C++ ref: ``ActionInferTypes::apply`` in coreaction.cc
    This is the main type propagation engine. It builds local types, propagates
    them across PcodeOp edges, propagates across RETURN ops, and writes back.
    """
    def __init__(self, g):
        super().__init__(0, "infertypes", g)
        self._localcount: int = 0

    def reset(self, data):
        super().reset(data)
        self._localcount = 0

    def clone(self, gl):
        return ActionInferTypes(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def _buildLocaltypes(data) -> None:
        """Set up initial temp types based on local info for each Varnode."""
        typegrp = data.getArch().types if hasattr(data.getArch(), 'types') else None
        for vn in data.beginLoc():
            if vn.isAnnotation():
                continue
            if not (vn._flags & 0x10) and vn.hasNoDescend():
                continue
            needsBlock = False
            entry = vn.getSymbolEntry()
            ct = None
            if entry is not None and not vn.isTypeLock():
                sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
                if sym is not None and hasattr(sym, 'isTypeLocked') and sym.isTypeLocked():
                    curOff = (vn.getAddr().getOffset() - entry.getAddr().getOffset())
                    if hasattr(entry, 'getOffset'):
                        curOff += entry.getOffset()
                    if typegrp is not None and hasattr(typegrp, 'getExactPiece'):
                        ct = typegrp.getExactPiece(sym.getType(), curOff, vn.getSize())
                    if ct is not None and hasattr(ct, 'getMetatype'):
                        from ghidra.types.datatype import TYPE_UNKNOWN
                        if ct.getMetatype() == TYPE_UNKNOWN:
                            ct = None
            if ct is None:
                result = vn.getLocalType(needsBlock)
                if isinstance(result, tuple):
                    ct, needsBlock = result
                else:
                    ct = result
            if needsBlock:
                vn.setStopUpPropagation()
            if ct is not None:
                vn.setTempType(ct)

    @staticmethod
    def _writeBack(data) -> bool:
        """Copy temp data-types to permanent field. Returns True if anything changed."""
        change = False
        for vn in data.beginLoc():
            if vn.isAnnotation():
                continue
            if not (vn._flags & 0x10) and vn.hasNoDescend():
                continue
            ct = vn.getTempType()
            if ct is None:
                continue
            if vn.updateType(ct):
                change = True
        return change

    @staticmethod
    def _propagateTypeEdge(typegrp, op, inslot: int, outslot: int) -> bool:
        """Attempt to propagate a data-type across a single PcodeOp edge."""
        ins = op._inrefs
        invn = op._output if inslot == -1 else ins[inslot]
        if invn is None:
            return False
        alttype = invn._temp_dataType
        if alttype is None:
            return False
        if hasattr(alttype, 'needsResolution') and alttype.needsResolution():
            if hasattr(alttype, 'resolveInFlow'):
                alttype = alttype.resolveInFlow(op, inslot)
        if inslot == outslot:
            return False
        if outslot < 0:
            outvn = op._output
        else:
            outvn = ins[outslot] if outslot < len(ins) else None
            if outvn is not None and (outvn._flags & _VN_ANNOT):  # isAnnotation
                return False
        if outvn is None:
            return False
        if outvn.isTypeLock():
            return False
        if outslot >= 0 and (outvn._addlflags & _VN_STOP_UP):  # stopsUpPropagation
            return False
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() == _TYPE_BOOL:
            if outvn._nzm > 1:
                return False
        opcode_obj = op._opcode
        newtype = None
        if opcode_obj is not None and hasattr(opcode_obj, 'propagateType'):
            newtype = opcode_obj.propagateType(alttype, op, invn, outvn, inslot, outslot)
        if newtype is None:
            return False
        outvn_temp = outvn._temp_dataType
        if outvn_temp is not None and hasattr(newtype, 'typeOrder'):
            if newtype.typeOrder(outvn_temp) < 0:
                outvn._temp_dataType = newtype
                return not outvn.isMark()
        return False

    @staticmethod
    def _propagateOneType(typegrp, vn) -> None:
        """Propagate a data-type from one Varnode across the function data-flow."""
        state = [_PropState(vn)]
        vn._flags |= _VN_MARK_PS
        while state:
            ptr = state[-1]
            if not ptr.valid():
                ptr.vn._flags &= ~_VN_MARK_PS
                state.pop()
            else:
                if ActionInferTypes._propagateTypeEdge(typegrp, ptr.op, ptr.inslot, ptr.slot):
                    nextvn = ptr.op._output if ptr.slot == -1 else ptr.op._inrefs[ptr.slot]
                    ptr.step()
                    state.append(_PropState(nextvn))
                    nextvn._flags |= _VN_MARK_PS
                else:
                    ptr.step()

    @staticmethod
    def _canonicalReturnOp(data):
        """Return the CPUI_RETURN op with the most specialized data-type."""
        from ghidra.core.opcodes import OpCode
        res = None
        bestdt = None
        for retop in data.beginOp(OpCode.CPUI_RETURN):
            if retop.isDead():
                continue
            if hasattr(retop, 'getHaltType') and retop.getHaltType() != 0:
                continue
            if retop.numInput() > 1:
                vn = retop.getIn(1)
                ct = vn.getTempType() if hasattr(vn, 'getTempType') else None
                if ct is None:
                    continue
                if bestdt is None:
                    res = retop
                    bestdt = ct
                elif hasattr(ct, 'typeOrder') and ct.typeOrder(bestdt) < 0:
                    res = retop
                    bestdt = ct
        return res

    @staticmethod
    def _propagateAcrossReturns(data) -> None:
        """Propagate data-types between CPUI_RETURN operations."""
        from ghidra.core.opcodes import OpCode
        proto = data.getFuncProto()
        if proto.isOutputLocked():
            return
        op = ActionInferTypes._canonicalReturnOp(data)
        if op is None:
            return
        typegrp = data.getArch().types if hasattr(data.getArch(), 'types') else None
        if typegrp is None:
            return
        baseVn = op.getIn(1)
        ct = baseVn.getTempType() if hasattr(baseVn, 'getTempType') else None
        if ct is None:
            return
        baseSize = baseVn.getSize()
        from ghidra.types.datatype import TYPE_BOOL
        isBool = hasattr(ct, 'getMetatype') and ct.getMetatype() == TYPE_BOOL
        for retop in data.beginOp(OpCode.CPUI_RETURN):
            if retop is op:
                continue
            if retop.isDead():
                continue
            if hasattr(retop, 'getHaltType') and retop.getHaltType() != 0:
                continue
            if retop.numInput() > 1:
                vn = retop.getIn(1)
                if vn.getSize() != baseSize:
                    continue
                if isBool and vn.getNZMask() > 1:
                    continue
                vntemp = vn.getTempType() if hasattr(vn, 'getTempType') else None
                if vntemp is ct:
                    continue
                if hasattr(vn, 'setTempType'):
                    vn.setTempType(ct)
                ActionInferTypes._propagateOneType(typegrp, vn)

    def apply(self, data):
        if hasattr(data, 'hasTypeRecoveryStarted') and not data.hasTypeRecoveryStarted():
            return 0
        typegrp = data.getArch().types if hasattr(data.getArch(), 'types') else None
        if typegrp is None:
            return 0
        if self._localcount >= 7:
            if self._localcount == 7:
                if hasattr(data, 'warningHeader'):
                    data.warningHeader("Type propagation algorithm not settling")
                if hasattr(data, 'setTypeRecoveryExceeded'):
                    data.setTypeRecoveryExceeded()
                self._localcount += 1
            return 0
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if localmap is not None and hasattr(localmap, 'applyTypeRecommendations'):
            localmap.applyTypeRecommendations()
        self._buildLocaltypes(data)
        for vn in data.beginLoc():
            if vn.isAnnotation():
                continue
            if not (vn._flags & 0x10) and vn.hasNoDescend():
                continue
            self._propagateOneType(typegrp, vn)
        self._propagateAcrossReturns(data)
        if localmap is not None and hasattr(localmap, 'getSpaceId'):
            spcid = localmap.getSpaceId()
            if hasattr(data, 'findSpacebaseInput'):
                spcvn = data.findSpacebaseInput(spcid)
                if spcvn is not None:
                    self._propagateSpacebaseRef(data, spcvn)
        if self._writeBack(data):
            self._localcount += 1
        return 0

    @staticmethod
    def _propagateSpacebaseRef(data, spcvn) -> None:
        """Search for pointers off spacebase and propagate data-types."""
        from ghidra.core.opcodes import OpCode
        from ghidra.types.datatype import TYPE_PTR, TYPE_SPACEBASE
        spctype = spcvn.getType()
        if spctype is None or not hasattr(spctype, 'getMetatype'):
            return
        if spctype.getMetatype() != TYPE_PTR:
            return
        if not hasattr(spctype, 'getPtrTo'):
            return
        inner = spctype.getPtrTo()
        if inner is None or not hasattr(inner, 'getMetatype'):
            return
        if inner.getMetatype() != TYPE_SPACEBASE:
            return
        for op in spcvn.getDescendants():
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
                if hasattr(inner, 'getAddress'):
                    addr = inner.getAddress(0, vn.getSize(), op.getAddr())
                    ActionInferTypes._propagateRef(data, op.getOut(), addr)
            elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB):
                vn = op.getIn(1)
                if vn.isConstant() and hasattr(inner, 'getAddress'):
                    addr = inner.getAddress(vn.getOffset(), vn.getSize(), op.getAddr())
                    ActionInferTypes._propagateRef(data, op.getOut(), addr)
            elif opc == OpCode.CPUI_PTRADD:
                vn = op.getIn(1)
                if vn.isConstant() and hasattr(inner, 'getAddress'):
                    off = vn.getOffset() * op.getIn(2).getOffset()
                    addr = inner.getAddress(off, vn.getSize(), op.getAddr())
                    ActionInferTypes._propagateRef(data, op.getOut(), addr)

    @staticmethod
    def _propagateRef(data, vn, addr) -> None:
        """Propagate pointer data-type to Varnodes at a known alias address."""
        from ghidra.types.datatype import TYPE_PTR, TYPE_SPACEBASE, TYPE_UNKNOWN
        ct = vn.getTempType() if hasattr(vn, 'getTempType') else None
        if ct is None or not hasattr(ct, 'getMetatype'):
            return
        if ct.getMetatype() != TYPE_PTR:
            return
        if not hasattr(ct, 'getPtrTo'):
            return
        ptrto = ct.getPtrTo()
        if ptrto is None:
            return
        meta = ptrto.getMetatype() if hasattr(ptrto, 'getMetatype') else None
        if meta == TYPE_SPACEBASE or meta == TYPE_UNKNOWN:
            return
        typegrp = data.getArch().types if hasattr(data.getArch(), 'types') else None
        if typegrp is None:
            return
        for curvn in data.beginLoc():
            if curvn.isAnnotation():
                continue
            if not curvn.isWritten() and curvn.hasNoDescend():
                continue
            if curvn.isTypeLock():
                continue
            if hasattr(curvn, 'getSymbolEntry') and curvn.getSymbolEntry() is not None:
                continue
            curoff = curvn.getOffset() - addr.getOffset()
            cursize = curvn.getSize()
            if curoff < 0 or curoff + cursize > ptrto.getSize():
                continue
            if typegrp is not None and hasattr(typegrp, 'getExactPiece'):
                lastct = typegrp.getExactPiece(ptrto, curoff, cursize)
            else:
                lastct = None
            if lastct is None:
                continue
            curvn_temp = curvn.getTempType() if hasattr(curvn, 'getTempType') else None
            if curvn_temp is not None and hasattr(lastct, 'typeOrder'):
                if lastct.typeOrder(curvn_temp) < 0:
                    curvn.setTempType(lastct)
                    ActionInferTypes._propagateOneType(typegrp, curvn)
