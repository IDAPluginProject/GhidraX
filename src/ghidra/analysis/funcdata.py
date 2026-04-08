"""
Corresponds to: funcdata.hh / funcdata.cc / funcdata_block.cc / funcdata_op.cc / funcdata_varnode.cc

Container for data structures associated with a single function.
Holds control-flow, data-flow, and prototype information.
"""

from __future__ import annotations

import os
import struct as _struct
import sys
from typing import TYPE_CHECKING, Optional, List, Iterator

_PTR_SIZE: int = _struct.calcsize('P')  # sizeof(void*): 8 on 64-bit, 4 on 32-bit
_FUNC_INSERT_DEBUG = os.environ.get("PYGHIDRA_DEBUG_HERITAGE_ORDER", "")
_SYNC_DEBUG_ADDRS = os.environ.get("PYGHIDRA_SYNC_DEBUG_ADDRS", "").strip()
_SYNC_DEBUG_LOG = os.environ.get("PYGHIDRA_SYNC_DEBUG_LOG", "D:/BIGAI/pyghidra/temp/python_sync_debug.log")
_PARAMUSE_DEBUG = os.environ.get("PYGHIDRA_PARAMUSE_DEBUG", "").strip()
_PARAMUSE_DEBUG_LOG = os.environ.get("PYGHIDRA_PARAMUSE_DEBUG_LOG", "D:/BIGAI/pyghidra/temp/python_paramuse_debug.log")
_UNIQUE_DEBUG_ADDRS = os.environ.get("PYGHIDRA_DEBUG_UNIQUE_ADDRS", "").strip()
_UNIQUE_DEBUG_SEQS = os.environ.get("PYGHIDRA_DEBUG_UNIQUE_SEQS", "").strip()
_UNIQUE_DEBUG_LOG = os.environ.get("PYGHIDRA_DEBUG_UNIQUE_LOG", "").strip()
_RESTART_DEBUG_FUNCS = os.environ.get("PYGHIDRA_DEBUG_RESTART_FUNCS", "").strip()
_RESTART_DEBUG_LOG = os.environ.get("PYGHIDRA_DEBUG_RESTART_LOG", "").strip()


def _parse_debug_int_set(raw: str) -> set[int]:
    values: set[int] = set()
    if not raw:
        return values
    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        try:
            values.add(int(token, 0))
        except ValueError:
            continue
    return values


_UNIQUE_DEBUG_ADDR_SET = _parse_debug_int_set(_UNIQUE_DEBUG_ADDRS)
_UNIQUE_DEBUG_SEQ_SET = _parse_debug_int_set(_UNIQUE_DEBUG_SEQS)
_RESTART_DEBUG_FUNC_SET = _parse_debug_int_set(_RESTART_DEBUG_FUNCS)


def _format_unique_debug_vn(vn: Optional[Varnode]) -> str:
    if vn is None:
        return "void"
    spc = vn.getSpace() if hasattr(vn, "getSpace") else None
    spc_name = spc.getName() if spc is not None and hasattr(spc, "getName") else "none"
    return f"{spc_name}[0x{vn.getOffset():x}:{vn.getSize()}]"


def _format_unique_debug_op(op: Optional[PcodeOp]) -> str:
    if op is None:
        return "op=<none>"
    addr = op.getAddr().getOffset() if hasattr(op, "getAddr") else -1
    seq = op.getTime() if hasattr(op, "getTime") else -1
    opc = op.code() if hasattr(op, "code") else "?"
    return f"op=@0x{addr:x}#{seq} opc={opc}"


def _should_log_unique_debug(op: Optional[PcodeOp]) -> bool:
    if not _UNIQUE_DEBUG_LOG:
        return False
    if not _UNIQUE_DEBUG_ADDR_SET and not _UNIQUE_DEBUG_SEQ_SET:
        return True
    if op is None:
        return False
    addr = op.getAddr().getOffset() if hasattr(op, "getAddr") else None
    seq = op.getTime() if hasattr(op, "getTime") else None
    if _UNIQUE_DEBUG_ADDR_SET and addr not in _UNIQUE_DEBUG_ADDR_SET:
        return False
    if _UNIQUE_DEBUG_SEQ_SET and seq not in _UNIQUE_DEBUG_SEQ_SET:
        return False
    return True


def _append_unique_debug_line(line: str) -> None:
    if not _UNIQUE_DEBUG_LOG:
        return
    try:
        with open(_UNIQUE_DEBUG_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
    except OSError:
        pass


def _unique_debug_caller(depth: int = 1) -> str:
    try:
        frame = sys._getframe(depth)
    except ValueError:
        return "caller=<unknown>"
    module = frame.f_globals.get("__name__", "<module>")
    return f"caller={module}.{frame.f_code.co_name}"


def _should_log_restart_debug(fd: Optional["Funcdata"]) -> bool:
    if not _RESTART_DEBUG_LOG:
        return False
    if not _RESTART_DEBUG_FUNC_SET:
        return True
    if fd is None:
        return False
    try:
        func_addr = fd.getAddress().getOffset()
    except Exception:
        return False
    return func_addr in _RESTART_DEBUG_FUNC_SET


def _append_restart_debug_line(line: str) -> None:
    if not _RESTART_DEBUG_LOG:
        return
    try:
        with open(_RESTART_DEBUG_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.write("\n")
    except OSError:
        pass


def _restart_debug_caller(depth: int = 1) -> str:
    try:
        frame = sys._getframe(depth)
    except ValueError:
        return "caller=<unknown>"
    module = frame.f_globals.get("__name__", "<module>")
    return f"caller={module}.{frame.f_code.co_name}"


def _debug_insert_event(kind: str, op: PcodeOp, anchor: PcodeOp, bl: Optional[BlockBasic]) -> None:
    if not _FUNC_INSERT_DEBUG:
        return
    seq = op.getSeqNum()
    outvn = op.getOut()
    out_text = "void"
    if outvn is not None:
        spc = outvn.getSpace()
        out_text = f"{spc.getName() if spc is not None else 'none'}[0x{outvn.getOffset():x}:{outvn.getSize()}]"
    anchor_seq = anchor.getSeqNum()
    block_len = len(bl.getOpList()) if bl is not None and hasattr(bl, "getOpList") else -1
    if seq.getAddr().getOffset() != 0x100401010 and anchor_seq.getAddr().getOffset() != 0x100401010:
        return
    print(
        f"{kind} op=@0x{seq.getAddr().getOffset():x} out={out_text} opc={op.code()} "
        f"anchor=@0x{anchor_seq.getAddr().getOffset():x} anchor_opc={anchor.code()} block_ops={block_len}",
        file=sys.stderr,
    )


def _sync_debug_should_log(vn) -> bool:
    if not _SYNC_DEBUG_ADDRS:
        return False
    try:
        off = vn.getAddr().getOffset()
    except Exception:
        return False
    if _SYNC_DEBUG_ADDRS == "*":
        return True
    for part in _SYNC_DEBUG_ADDRS.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            if off == int(part, 0):
                return True
        except Exception:
            continue
    return False


def _sync_debug_log(vn, message: str) -> None:
    if not _sync_debug_should_log(vn):
        return
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        addr = vn.getAddr()
        spc = addr.getSpace()
        text = f"{spc.getName() if spc is not None else 'none'}[{addr.getOffset():#x}:{vn.getSize()}]"
    except Exception:
        text = "?"
    try:
        with open(_SYNC_DEBUG_LOG, "a", encoding="utf-8") as fp:
            prefix = "[sync]"
            if idx > 0:
                prefix += f" idx={idx}"
            fp.write(f"{prefix} vn={text} {message}\n")
    except Exception:
        return


def _sync_debug_group_log(vnlist, message: str) -> None:
    if not vnlist:
        return
    exemplar = vnlist[0]
    if not _sync_debug_should_log(exemplar):
        return
    parts = []
    for idx, vn in enumerate(vnlist):
        try:
            role = "in" if vn.isInput() else "wr" if vn.isWritten() else "free" if vn.isFree() else "oth"
        except Exception:
            role = "?"
        try:
            flags = vn.getFlags()
        except Exception:
            flags = -1
        try:
            mapentry = int(vn.getSymbolEntry() is not None)
        except Exception:
            mapentry = -1
        parts.append(f"{idx}:{role}:flags={flags:#x}:map={mapentry}")
    _sync_debug_log(exemplar, f"{message} group=[{' ; '.join(parts)}]")


def _sync_debug_rangelist(rangelist) -> str:
    try:
        if rangelist is None or rangelist.empty():
            return "[]"
        parts = []
        for rng in rangelist:
            space = getattr(rng, "spc", None)
            space_name = space.getName() if space is not None and hasattr(space, "getName") else "?"
            parts.append(f"{space_name}[{rng.getFirst():#x},{rng.getLast():#x}]")
        return "[" + ", ".join(parts) + "]"
    except Exception:
        return "<?>"


def _is_unknown_datatype(ct) -> bool:
    if ct is None or not hasattr(ct, "getMetatype"):
        return False
    meta = ct.getMetatype()
    try:
        from ghidra.types.datatype import TYPE_UNKNOWN

        if meta == TYPE_UNKNOWN:
            return True
    except Exception:
        pass
    if isinstance(meta, str):
        return meta.lower() == "unknown"
    name = getattr(meta, "name", None)
    if isinstance(name, str) and name.upper() == "TYPE_UNKNOWN":
        return True
    return meta == 15


def _paramuse_debug_enabled(opmatch, trial) -> bool:
    if not _PARAMUSE_DEBUG:
        return False
    if _PARAMUSE_DEBUG == "*":
        return True
    try:
        op_part, trial_part = _PARAMUSE_DEBUG.split("/", 1)
        op_off = opmatch.getAddr().getOffset()
        trial_off = trial.getAddress().getOffset()
        return op_off == int(op_part, 0) and trial_off == int(trial_part, 0)
    except Exception:
        return False


def _paramuse_debug_log(opmatch, trial, message: str) -> None:
    if not _paramuse_debug_enabled(opmatch, trial):
        return
    try:
        with open(_PARAMUSE_DEBUG_LOG, "a", encoding="utf-8") as fp:
            fp.write(f"{message}\n")
    except Exception:
        return

from ghidra.core.address import Address, SeqNum
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_INTERNAL
from ghidra.ir.varnode import Varnode, VarnodeBank
from ghidra.ir.op import PcodeOp, PcodeOpBank, PieceNode
from ghidra.ir.variable import HighVariable
from ghidra.block.block import BlockBasic, BlockGraph, FlowBlock
from ghidra.fspec.fspec import FuncProto, FuncCallSpecs

if TYPE_CHECKING:
    from ghidra.database.database import Scope, FunctionSymbol
    from ghidra.types.datatype import Datatype


class Funcdata:
    """Container for data structures associated with a single function.

    Holds control-flow, data-flow, and prototype information, plus class
    instances to help with SSA form, structure control-flow, recover
    jump-tables, recover parameters, and merge Varnodes.
    """

    # Internal flags
    highlevel_on = 1
    blocks_generated = 2
    blocks_unreachable = 4
    processing_started = 8
    processing_complete = 0x10
    typerecovery_on = 0x20
    typerecovery_start = 0x40
    no_code = 0x80
    jumptablerecovery_on = 0x100
    jumptablerecovery_dont = 0x200
    restart_pending = 0x400
    unimplemented_present = 0x800
    baddata_present = 0x1000
    double_precis_on = 0x2000
    typerecovery_exceeded = 0x4000

    def __init__(self, nm: str, disp: str, scope: Optional[Scope],
                 addr: Address, sym: Optional[FunctionSymbol] = None,
                 sz: int = 0) -> None:
        parent_scope = scope
        glb = parent_scope.getArch() if parent_scope is not None and hasattr(parent_scope, 'getArch') else None

        self._flags: int = 0
        self._clean_up_index: int = 0
        self._high_level_index: int = 0
        self._cast_phase_index: int = 0
        self._minLanedSize: int = (
            glb.getMinimumLanedRegisterSize()
            if glb is not None and hasattr(glb, 'getMinimumLanedRegisterSize')
            else 0
        )
        self._size: int = sz
        self._glb = glb
        self._functionSymbol = sym
        self._name: str = nm
        self._displayName: str = disp
        self._baseaddr: Address = addr
        self._funcp: FuncProto = FuncProto()
        self._localmap: Optional[Scope] = None

        self._qlst: List[FuncCallSpecs] = []
        self._qlst_map: dict = {}  # PcodeOp id -> FuncCallSpecs
        self._iop_lookup: dict = {}  # id(op) -> PcodeOp for IOP space lookup
        self._jumpvec = []  # List[JumpTable]
        self._localoverride = None  # Override
        self._override = None  # Backward-compatible alias of _localoverride
        self._unionMap = None  # UnionResolveMap
        self._lanedMap = {}
        from ghidra.analysis.heritage import Heritage
        self._heritage = Heritage(self)
        self._jtcallback = None
        self._modify_list = []
        self._modify_before = []
        self._opactdbg_count = 0
        self._opactdbg_breakcount = -1
        self._opactdbg_on = False
        self._opactdbg_active = False
        self._opactdbg_breakon = False
        self._opactdbg_pclow = []
        self._opactdbg_pchigh = []
        self._opactdbg_uqlow = []
        self._opactdbg_uqhigh = []
        self._activeoutput = None

        self._vbank: VarnodeBank = VarnodeBank(glb)
        self._obank: PcodeOpBank = PcodeOpBank()
        self._bblocks: BlockGraph = BlockGraph()
        self._sblocks: BlockGraph = BlockGraph()
        from ghidra.analysis.merge import Merge
        self._covermerge = Merge(self)

        if nm == "":
            self._localmap = None
        elif parent_scope is not None and glb is not None:
            stack_spc = glb.getStackSpace() if hasattr(glb, 'getStackSpace') else None
            if stack_spc is not None:
                if sym is not None and hasattr(sym, 'getId'):
                    scope_id = sym.getId()
                else:
                    scope_id = (0x57AB12CD << 32) | (addr.getOffset() & 0xFFFFFFFF)
                from ghidra.database.varmap import ScopeLocal
                localmap = ScopeLocal(scope_id, stack_spc, self, glb)
                if hasattr(parent_scope, 'attachScope'):
                    parent_scope.attachScope(localmap)
                db = getattr(glb, 'symboltab', None)
                if db is not None and hasattr(db, '_scopeMap'):
                    db._scopeMap[localmap.getId() if hasattr(localmap, 'getId') else localmap.uniqueId] = localmap
                self._localmap = localmap
                if hasattr(self._funcp, 'setScope'):
                    self._funcp.setScope(self._localmap, self._baseaddr + -1)
                if hasattr(self._localmap, 'resetLocalWindow'):
                    self._localmap.resetLocalWindow()
            else:
                self._localmap = parent_scope
        else:
            self._localmap = parent_scope

    def __del__(self) -> None:
        try:
            localmap = getattr(self, "_localmap", None)
            glb = getattr(self, "_glb", None)
            if localmap is not None and glb is not None:
                symboltab = getattr(glb, "symboltab", None)
                if symboltab is not None:
                    if hasattr(symboltab, "deleteScope"):
                        symboltab.deleteScope(localmap)
                    elif hasattr(symboltab, "removeScope"):
                        symboltab.removeScope(localmap)

            if hasattr(self, "clearCallSpecs"):
                self.clearCallSpecs()

            jumpvec = getattr(self, "_jumpvec", None)
            if jumpvec is not None:
                jumpvec.clear()

            self._glb = None
        except Exception:
            # Python finalizers should not leak exceptions during GC shutdown.
            pass

    # --- Basic accessors ---

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._displayName

    def getAddress(self) -> Address:
        return self._baseaddr

    def getSize(self) -> int:
        return self._size

    def getArch(self):
        return self._glb

    def setArch(self, glb) -> None:
        self._glb = glb
        if getattr(self, "_vbank", None) is not None:
            self._vbank._manage = glb
            if glb is not None and hasattr(glb, "getUniqueSpace"):
                self._vbank._uniq_space = glb.getUniqueSpace()
            if glb is not None and hasattr(glb, "getUniqueBase"):
                uniq_base = glb.getUniqueBase()
                self._vbank._uniqbase = uniq_base
                if getattr(self._vbank, "_uniq_id", 0) == 0:
                    self._vbank._uniq_id = uniq_base
        # Auto-create a ScopeLocal if none exists yet
        if self._localmap is None and glb is not None:
            stack_spc = glb.getStackSpace() if hasattr(glb, 'getStackSpace') else None
            if stack_spc is not None:
                from ghidra.database.varmap import ScopeLocal
                self._localmap = ScopeLocal(0, stack_spc, self, glb)
                # Attach to global scope so isGlobal() returns False.
                # Without this, queryProperties falls back to setting persist on
                # ALL unrecognised register addresses (flags, segment regs, etc.),
                # which causes Heritage to create addrforce COPY guards for them
                # and dead-code removal to leave them alive in the output.
                # C++ ref: Funcdata ctor attaches ScopeLocal to the Database tree.
                db = getattr(glb, 'symboltab', None)
                if db is not None:
                    global_scope = db.getGlobalScope() if hasattr(db, 'getGlobalScope') else None
                    if global_scope is not None and hasattr(global_scope, 'attachScope'):
                        global_scope.attachScope(self._localmap)
        if (self._localmap is not None and self._funcp is not None
                and hasattr(self._funcp, 'hasModel') and not self._funcp.hasModel()
                and glb is not None and hasattr(glb, 'defaultfp')):
            self._funcp.setModel(glb.defaultfp)
        if self._localmap is not None and hasattr(self._localmap, 'resetLocalWindow'):
            self._localmap.resetLocalWindow()

    def getSymbol(self):
        return self._functionSymbol

    def getVarnodeBank(self):
        return self._vbank

    def getOpBank(self):
        return self._obank

    def getOverride(self):
        localoverride = getattr(self, '_localoverride', None)
        if localoverride is None:
            localoverride = getattr(self, '_override', None)
        if localoverride is None:
            from ghidra.arch.override import Override
            localoverride = Override()
        self._localoverride = localoverride
        self._override = localoverride
        return localoverride

    def getJumpTable(self, ind):
        """Get the i-th JumpTable."""
        return self._jumpvec[ind]

    def getJumpTables(self):
        return self._jumpvec

    def installJumpTable(self, addr):
        from ghidra.core.error import LowlevelError
        from ghidra.analysis.jumptable import JumpTable
        if self.isProcStarted():
            raise LowlevelError("Cannot install jumptable if flow is already traced")
        for jt in self._jumpvec:
            if jt.getOpAddress() == addr:
                raise LowlevelError("Trying to install over existing jumptable")
        jt = JumpTable(self._glb, addr)
        self._jumpvec.append(jt)
        return jt

    def getCallSpecs(self, op_or_index):
        """Look up FuncCallSpecs by PcodeOp or by integer index.

        C++ has two overloads:
          FuncCallSpecs *getCallSpecs(const PcodeOp *op)
          FuncCallSpecs *getCallSpecs(int4 i)
        """
        if isinstance(op_or_index, int):
            return self._qlst[op_or_index]
        from ghidra.core.space import IPTR_FSPEC
        op = op_or_index
        vn = op.getIn(0)
        if vn.getSpace().getType() == IPTR_FSPEC:
            return FuncCallSpecs.getFspecFromConst(vn.getAddr())
        for fc in self._qlst:
            if fc.getOp() is op:
                return fc
        return None

    def addCallSpecs(self, fc):
        """Register a FuncCallSpecs for this function."""
        self._qlst.append(fc)
        if hasattr(FuncCallSpecs, 'registerFspecRef'):
            FuncCallSpecs.registerFspecRef(fc)
        if hasattr(fc, 'getOp') and fc.getOp() is not None:
            self._qlst_map[id(fc.getOp())] = fc

    def setUnionField(self, dt, op, slot, res):
        """Associate a union field with the given edge.

        If there was a previous locked association, returns False.
        For MULTIEQUAL ops, copies resolution to other input slots
        holding the same Varnode.

        C++ ref: ``Funcdata::setUnionField``
        """
        if self._unionMap is None:
            from ghidra.types.resolve import UnionResolveMap
            self._unionMap = UnionResolveMap()
        # Check for locked previous association
        existing = self._unionMap.getUnionField(dt, op, slot)
        if existing is not None and existing.isLocked():
            return False
        self._unionMap.setUnionField(dt, op, slot, res)
        # MULTIEQUAL: copy resolution to other slots holding same Varnode
        if op.code() == OpCode.CPUI_MULTIEQUAL and slot >= 0:
            vn = op.getIn(slot)
            for i in range(op.numInput()):
                if i == slot:
                    continue
                if op.getIn(i) is not vn:
                    continue
                dup_existing = self._unionMap.getUnionField(dt, op, i)
                if dup_existing is not None and dup_existing.isLocked():
                    continue
                self._unionMap.setUnionField(dt, op, i, res)
        return True

    def getUnionField(self, dt, op, slot):
        if self._unionMap is None:
            return None
        return self._unionMap.getUnionField(dt, op, slot)

    def getFirstReturnOp(self):
        """Return the first non-dead, non-halt RETURN op, or None.

        C++ ref: ``Funcdata::getFirstReturnOp``
        """
        from ghidra.core.opcodes import OpCode

        for op in self.beginOp(OpCode.CPUI_RETURN):
            if op.isDead():
                continue
            if op.getHaltType() != 0:
                continue
            return op
        return None

    def getFuncProto(self) -> FuncProto:
        return self._funcp

    def getLocalScope(self):
        return self._localmap

    def getScopeLocal(self):
        return self._localmap

    def getBasicBlocks(self) -> BlockGraph:
        return self._bblocks

    def getStructure(self) -> BlockGraph:
        return self._sblocks

    # --- Flag queries ---

    def isHighOn(self) -> bool:
        return (self._flags & Funcdata.highlevel_on) != 0

    def isProcStarted(self) -> bool:
        return (self._flags & Funcdata.processing_started) != 0

    def isProcComplete(self) -> bool:
        return (self._flags & Funcdata.processing_complete) != 0

    def hasUnreachableBlocks(self) -> bool:
        return (self._flags & Funcdata.blocks_unreachable) != 0

    def isTypeRecoveryOn(self) -> bool:
        return (self._flags & Funcdata.typerecovery_on) != 0

    def hasTypeRecoveryStarted(self) -> bool:
        return (self._flags & Funcdata.typerecovery_start) != 0

    def hasNoCode(self) -> bool:
        return (self._flags & Funcdata.no_code) != 0

    def setNoCode(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.no_code
        else:
            self._flags &= ~Funcdata.no_code

    def hasRestartPending(self) -> bool:
        return (self._flags & Funcdata.restart_pending) != 0

    def setRestartPending(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.restart_pending
        else:
            self._flags &= ~Funcdata.restart_pending

    def hasUnimplemented(self) -> bool:
        return (self._flags & Funcdata.unimplemented_present) != 0

    def hasBadData(self) -> bool:
        return (self._flags & Funcdata.baddata_present) != 0

    def isDoublePrecisOn(self) -> bool:
        return (self._flags & Funcdata.double_precis_on) != 0

    def setTypeRecovery(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.typerecovery_on
        else:
            self._flags &= ~Funcdata.typerecovery_on

    def hasNoStructBlocks(self) -> bool:
        return self._sblocks.getSize() == 0

    # --- Processing lifecycle ---

    def startProcessing(self) -> None:
        """Start processing: generate raw p-code, build blocks, call specs.

        C++ ref: ``Funcdata::startProcessing``
        """
        from ghidra.core.address import Address
        from ghidra.core.error import LowlevelError

        if (self._flags & Funcdata.processing_started) != 0:
            raise LowlevelError("Function processing already started")
        self._flags |= Funcdata.processing_started

        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'isInline') and self._funcp.isInline():
            self.warningHeader("This is an inlined function")
        if self._localmap is not None and hasattr(self._localmap, 'clearUnlocked'):
            self._localmap.clearUnlocked()
        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'clearUnlockedOutput'):
            self._funcp.clearUnlockedOutput()
        if self._bblocks.getSize() == 0:
            baddr = Address(self._baseaddr.getSpace(), 0)
            eaddr = Address(self._baseaddr.getSpace(), 0xFFFFFFFFFFFFFFFF)
            self.followFlow(baddr, eaddr)
        self.structureReset()
        self.sortCallSpecs()
        if self._heritage is not None:
            self._heritage.buildInfoList()
        if hasattr(self, '_localoverride') and self._localoverride is not None and hasattr(self._localoverride, 'applyDeadCodeDelay'):
            self._localoverride.applyDeadCodeDelay(self)

    def stopProcessing(self) -> None:
        """Mark processing as complete, clean up dead ops, issue warnings.

        C++ ref: ``Funcdata::stopProcessing``
        """
        self._flags |= Funcdata.processing_complete
        if hasattr(self._obank, 'destroyDead'):
            self._obank.destroyDead()
        if not self.isJumptableRecoveryOn():
            self.issueDatatypeWarnings()

    def startTypeRecovery(self) -> bool:
        if (self._flags & Funcdata.typerecovery_start) != 0:
            return False
        self._flags |= Funcdata.typerecovery_start
        return True

    def startCastPhase(self) -> None:
        self._cast_phase_index = self._vbank.getCreateIndex()

    def startCleanUp(self) -> None:
        self._clean_up_index = self._vbank.getCreateIndex()

    def opHeritage(self) -> None:
        """Build SSA representation (heritage pass)."""
        self._heritage.heritage()

    def getHeritagePass(self) -> int:
        """Get the current heritage pass number."""
        return self._heritage.getPass()

    def setHighLevel(self) -> None:
        """Turn on HighVariable objects for all existing Varnodes.

        C++ ref: ``Funcdata::setHighLevel``
        """
        if (self._flags & Funcdata.highlevel_on) != 0:
            return
        self._flags |= Funcdata.highlevel_on
        self._high_level_index = self._vbank.getCreateIndex()
        for vn in self._vbank.beginLoc():
            self.assignHigh(vn)

    def getActiveOutput(self):
        """Get the active output parameter recovery object.

        C++ ref: ``Funcdata::getActiveOutput``
        """
        return self._activeoutput

    def initActiveOutput(self) -> None:
        """Initialize return prototype recovery analysis.

        C++ ref: ``Funcdata::initActiveOutput``
        """
        from ghidra.fspec.paramactive import ParamActive

        self._activeoutput = ParamActive(False)
        maxdelay = self._funcp.getMaxOutputDelay()
        if maxdelay > 0:
            maxdelay = 3
        self._activeoutput.setMaxPass(maxdelay)

    def clearActiveOutput(self) -> None:
        """Clear the active output recovery object."""
        self._activeoutput = None

    def clearDeadVarnodes(self) -> None:
        """Free any Varnodes not attached to anything.

        Input Varnodes that have no descendants and are not locked are
        demoted to free, then all free Varnodes with no descendants are
        destroyed.

        C++ ref: ``Funcdata::clearDeadVarnodes``
        """
        for vn in self._vbank.beginLoc():
            if vn.hasNoDescend():
                if vn.isInput() and not vn.isLockedInput():
                    self._vbank.makeFree(vn)
                    vn.clearCover()
                if vn.isFree():
                    self._vbank.destroy(vn)

    def calcNZMask(self) -> None:
        from ghidra.transform.nzmask import calcNZMask
        calcNZMask(self)

    def clearDeadOps(self) -> None:
        """Permanently destroy PcodeOps that have been marked as dead."""
        self._obank.destroyDead()

    def seenDeadcode(self, spc) -> None:
        """Record that dead code has been seen for a given space."""
        self._heritage.seenDeadCode(spc)

    def spacebase(self) -> None:
        """Mark Varnode objects that hold stack-pointer values as spacebase.

        For each address space that has a base register, find all Varnodes at
        the register's location/size.  Already-marked spacebases with an
        INT_ADD def get their uses split.  Unmarked ones are flagged as
        spacebase, and input varnodes additionally get the TypeSpacebase
        pointer type.

        C++ ref: ``Funcdata::spacebase``
        """
        from ghidra.ir.varnode import Varnode
        from ghidra.core.address import Address
        glb = self._glb
        if glb is None:
            return
        for j in range(glb.numSpaces()):
            spc = glb.getSpace(j)
            if spc is None:
                continue
            numspace = getattr(spc, 'numSpacebase', lambda: 0)()
            for i in range(numspace):
                point = spc.getSpacebase(i)
                addr = Address(point.space, point.offset)
                if hasattr(self._vbank, "beginLocSize"):
                    get_varnodes = lambda: list(self._vbank.beginLocSize(point.size, addr))
                else:
                    get_varnodes = lambda: [
                        vn
                        for vn in self._vbank.beginLoc()
                        if vn.getAddr() == addr and vn.getSize() == point.size
                    ]
                # Build pointer-to-spacebase type
                ptr = None
                if hasattr(glb, 'types') and glb.types is not None:
                    ct = glb.types.getTypeSpacebase(spc, self.getAddress()) if hasattr(glb.types, 'getTypeSpacebase') else None
                    if ct is not None and hasattr(glb.types, 'getTypePointer'):
                        wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                        ptr = glb.types.getTypePointer(point.size, ct, wordSize)
                # Iterate over the current loc/size range.  If splitUses()
                # materializes additional varnodes in the same range, refresh
                # the range so they are handled in this pass like native.
                varnodes = get_varnodes()
                idx = 0
                while idx < len(varnodes):
                    vn = varnodes[idx]
                    idx += 1
                    if vn.isFree():
                        continue
                    if vn.isSpacebase():
                        # Already marked -- split uses if def is INT_ADD
                        defop = vn.getDef()
                        if defop is not None and defop.code() == OpCode.CPUI_INT_ADD:
                            descendants = list(vn.getDescendants())
                            if len(descendants) > 1:
                                self.splitUses(vn)
                                varnodes = get_varnodes()
                                idx = 0
                    else:
                        vn.setFlags(Varnode.spacebase)
                        if vn.isInput() and ptr is not None:
                            vn.updateType(ptr, True, True)

    def structureReset(self) -> None:
        """Recalculate loop structure and dominance for the current CFG.

        The structured hierarchy is also reset. This can be called
        multiple times as changes are made to control-flow.

        C++ ref: ``Funcdata::structureReset``
        """
        self._flags &= ~Funcdata.blocks_unreachable
        rootlist = []
        self._bblocks.structureLoops(rootlist)
        self._bblocks.calcForwardDominator(rootlist)
        if len(rootlist) > 1:
            self._flags |= Funcdata.blocks_unreachable
        # Check for dead jumptables
        alivejumps = []
        for jt in self._jumpvec:
            indop = jt.getIndirectOp()
            if indop.isDead():
                self.warningHeader("Recovered jumptable eliminated as dead code")
                continue
            alivejumps.append(jt)
        self._jumpvec = alivejumps
        self._sblocks.clear()
        if self._heritage is None:
            from ghidra.analysis.heritage import Heritage

            self._heritage = Heritage(self)
        self._heritage.forceRestructure()

    def opZeroMulti(self, op) -> None:
        """Handle MULTIEQUAL with 0 or 1 inputs after edge removal."""
        if op.numInput() == 0:
            self.opInsertInput(op, self.newVarnode(op.getOut().getSize(), op.getOut().getAddr()), 0)
            self.setInputVarnode(op.getIn(0))
            self.opSetOpcode(op, OpCode.CPUI_COPY)
        elif op.numInput() == 1:
            self.opSetOpcode(op, OpCode.CPUI_COPY)

    def branchRemoveInternal(self, bb, num: int) -> None:
        """Remove outgoing branch edge, patch MULTIEQUAL ops in target block."""
        if bb.sizeOut() == 2:
            self.opDestroy(bb.lastOp())
        bbout = bb.getOut(num)
        blocknum = bbout.getInIndex(bb)
        self._bblocks.removeEdge(bb, bbout)
        for op in list(bbout.getOpList()):
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            self.opRemoveInput(op, blocknum)
            self.opZeroMulti(op)

    def removeUnreachableBlocks(self, issuewarning: bool, checkexistence: bool) -> bool:
        """Remove unreachable blocks from the control flow graph."""
        if checkexistence:
            for i in range(self._bblocks.getSize()):
                blk = self._bblocks.getBlock(i)
                if blk.isEntryPoint():
                    continue
                if blk.getImmedDom() is None:
                    break
            else:
                return False
        elif not self.hasUnreachableBlocks():
            return False

        unreachable = []
        for i in range(self._bblocks.getSize()):
            if self._bblocks.getBlock(i).isEntryPoint():
                break
        self._bblocks.collectReachable(unreachable, self._bblocks.getBlock(i), True)

        for bl in unreachable:
            bl.setDead()
            if issuewarning:
                start = bl.getStart()
                msg = f"Removing unreachable block ({start.getSpace().getName()},{start.printRaw()})"
                self.warningHeader(msg)
        for bl in unreachable:
            while bl.sizeOut() > 0:
                self.branchRemoveInternal(bl, 0)
        for bl in unreachable:
            self.blockRemoveInternal(bl, True)
        self.structureReset()
        return True

    def removeBranch(self, bb, num: int) -> None:
        """Remove a branch edge from a basic block."""
        self.branchRemoveInternal(bb, num)
        self.structureReset()

    def blockRemoveInternal(self, bb, unreachable: bool) -> None:
        """Remove an active basic block from the function.

        PcodeOps in the block are deleted.  Data-flow and control-flow
        are patched up.  MULTIEQUAL ops in successor blocks are adjusted.

        C++ ref: ``Funcdata::blockRemoveInternal``
        """
        # Check for BRANCHIND and associated jump table
        lastop = bb.lastOp() if hasattr(bb, 'lastOp') else None
        if lastop is not None and lastop.code() == OpCode.CPUI_BRANCHIND:
            jt = self.findJumpTable(lastop)
            if jt is not None:
                self.removeJumpTable(jt)

        if not unreachable:
            self.pushMultiequals(bb)
            # Patch MULTIEQUALs in successor blocks
            for i in range(bb.sizeOut()):
                bbout = bb.getOut(i)
                if hasattr(bbout, 'isDead') and bbout.isDead():
                    continue
                blocknum = bbout.getInIndex(bb)
                if hasattr(bbout, 'getOpList'):
                    for op in list(bbout.getOpList()):
                        if op.code() != OpCode.CPUI_MULTIEQUAL:
                            continue
                        if blocknum >= op.numInput():
                            continue
                        deadvn = op.getIn(blocknum)
                        self.opRemoveInput(op, blocknum)
                        deadop = deadvn.getDef() if deadvn is not None and deadvn.isWritten() else None
                        if (deadop is not None and deadop.code() == OpCode.CPUI_MULTIEQUAL
                                and deadop.getParent() == bb):
                            for j in range(bb.sizeIn()):
                                self.opInsertInput(op, deadop.getIn(j), op.numInput())
                        else:
                            for j in range(bb.sizeIn()):
                                self.opInsertInput(op, deadvn, op.numInput())
                        self.opZeroMulti(op)

        self._bblocks.removeFromFlow(bb)

        desc_warning = False
        if hasattr(bb, 'getOpList'):
            for op in list(bb.getOpList()):
                if op.isAssignment():
                    deadvn = op.getOut()
                    if deadvn is not None:
                        if unreachable:
                            undef = self.descend2Undef(deadvn)
                            if undef and not desc_warning:
                                self.warningHeader("Creating undefined varnodes in (possibly) reachable block")
                                desc_warning = True
                        if self.descendantsOutside(deadvn):
                            from ghidra.core.error import LowlevelError

                            raise LowlevelError("Deleting op with descendants\n")
                if op.isCall():
                    self.deleteCallSpecs(op)
                self.opDestroy(op)
        self._bblocks.removeBlock(bb)

    def spliceBlockBasic(self, bl) -> None:
        """Splice a block with its single successor, concatenating p-code.

        The given block must have a single output block with a single
        input. The output block's ops are appended to bl, and bl
        inherits the output block's out edges.

        C++ ref: ``Funcdata::spliceBlockBasic``
        """
        from ghidra.core.error import LowlevelError

        outbl = None
        if bl.sizeOut() == 1:
            outbl = bl.getOut(0)
            if outbl.sizeIn() != 1:
                outbl = None
        if outbl is None:
            raise LowlevelError("Cannot splice basic blocks")
        # Remove any jump op at the end of bl
        if bl.getOpList():
            jumpop = bl.lastOp()
            if jumpop.isBranch():
                self.opDestroy(jumpop)
        if outbl.getOpList():
            firstop = outbl.getOpList()[0]
            if firstop.code() == OpCode.CPUI_MULTIEQUAL:
                raise LowlevelError("Splicing block with MULTIEQUAL")
            firstop.clearFlag(PcodeOp.startbasic)
            # Reparent all ops from outbl to bl
            for op in list(outbl.getOpList()):
                op.setParent(bl)
            # Move all ops from outbl to end of bl
            bl_ops = bl.getOpList()
            out_ops = outbl.getOpList()
            bl_ops.extend(out_ops)
            out_ops.clear()
            bl.setOrder()
        bl.mergeRange(outbl)
        self._bblocks.spliceBlock(bl)
        self.structureReset()

    def removeDoNothingBlock(self, bb) -> None:
        """Remove a block that does nothing."""
        from ghidra.core.error import LowlevelError

        if bb.sizeOut() > 1:
            raise LowlevelError("Cannot delete a reachable block unless it has 1 out or less")
        bb.setDead()
        self.blockRemoveInternal(bb, False)
        self.structureReset()

    def deleteCallSpecs(self, op) -> None:
        """Remove call specs associated with the given op."""
        for i, cs in enumerate(self._qlst):
            if cs.getOp() is op:
                del self._qlst[i]
                return

    def clear(self) -> None:
        """Clear everything associated with decompilation (analysis).

        C++ ref: ``Funcdata::clear``
        """
        self._flags &= ~(Funcdata.highlevel_on | Funcdata.blocks_generated |
                         Funcdata.processing_started | Funcdata.typerecovery_start |
                         Funcdata.typerecovery_on | Funcdata.double_precis_on |
                         Funcdata.restart_pending)
        self._clean_up_index = 0
        self._high_level_index = 0
        self._cast_phase_index = 0
        if self._glb is not None and hasattr(self._glb, 'getMinimumLanedRegisterSize'):
            self._minLanedSize = self._glb.getMinimumLanedRegisterSize()

        if self._localmap is not None and hasattr(self._localmap, 'clearUnlocked'):
            self._localmap.clearUnlocked()
        if self._localmap is not None and hasattr(self._localmap, 'resetLocalWindow'):
            self._localmap.resetLocalWindow()

        self.clearActiveOutput()
        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'clearUnlockedOutput'):
            self._funcp.clearUnlockedOutput()
        if self._unionMap is not None:
            if hasattr(self._unionMap, 'clear'):
                self._unionMap.clear()
            else:
                self._unionMap = None
        self.clearBlocks()
        self._obank.clear()
        self._vbank.clear()
        self.clearCallSpecs()
        self.clearJumpTables()
        # Do not clear overrides
        if self._heritage is not None:
            self._heritage.clear()
        if hasattr(self, '_covermerge') and self._covermerge is not None and hasattr(self._covermerge, 'clear'):
            self._covermerge.clear()

    # --- Call specification routines ---

    def numCalls(self) -> int:
        return len(self._qlst)

    def getCallSpecsByIndex(self, i: int) -> Optional[FuncCallSpecs]:
        return self._qlst[i] if 0 <= i < len(self._qlst) else None

    # --- Varnode creation routines ---

    def newVarnode(self, s: int, addr: Address | AddrSpace, ct: Optional[Datatype | int] = None) -> Varnode:
        """Create a new unattached Varnode.

        C++ ref: ``Funcdata::newVarnode``
        """
        if not isinstance(addr, Address) and ct is not None and not hasattr(ct, 'getMetatype'):
            return self.newVarnode(s, Address(addr, int(ct)))

        from ghidra.types.datatype import TYPE_UNKNOWN

        if ct is None:
            ct = self._glb.types.getBase(s, TYPE_UNKNOWN)
        vn = self._vbank.create(s, addr, ct)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, addr)
        vflags_ref = [0]
        entry = self._localmap.queryProperties(vn.getAddr(), vn.getSize(), Address(), vflags_ref)
        vflags = vflags_ref[0]
        if entry is not None:
            vn.setSymbolProperties(entry)
        else:
            vn.setFlags(vflags & ~Varnode.typelock)
        return vn

    def newConstant(self, s: int, val: int) -> Varnode:
        """Create a new constant Varnode.

        C++ ref: ``Funcdata::newConstant``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        addr = Address(self._glb.getConstantSpace(), val)
        ct = self._glb.types.getBase(s, TYPE_UNKNOWN)
        vn = self._vbank.create(s, addr, ct)
        self.assignHigh(vn)
        return vn

    def newUnique(self, s: int, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new temporary Varnode in unique space.

        C++ ref: ``Funcdata::newUnique``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        if ct is None:
            ct = self._glb.types.getBase(s, TYPE_UNKNOWN)
        vn = self._vbank.createUnique(s, ct)
        if _should_log_unique_debug(None):
            base = vn.getAddr().getOffset() if hasattr(vn, "getAddr") else 0
            _append_unique_debug_line(
                f"event=newUnique size={s} base=0x{base:x} next=0x{base + s:x} {_unique_debug_caller(2)}"
            )
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, vn.getAddr())
        return vn

    def newVarnodeOut(self, s: int, addr: Address, op: PcodeOp) -> Varnode:
        """Create a new Varnode defined as output of a given PcodeOp.

        C++ ref: ``Funcdata::newVarnodeOut``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        ct = self._glb.types.getBase(s, TYPE_UNKNOWN) if self._glb is not None and hasattr(self._glb, 'types') else None
        vn = self._vbank.createDef(s, addr, ct, op)
        op.setOutput(vn)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, addr)
        if self._localmap is not None and hasattr(self._localmap, 'queryProperties'):
            vflags_ref = [0]
            entry = self._localmap.queryProperties(addr, s, op.getAddr(), vflags_ref)
            vflags = vflags_ref[0]
            if entry is not None and hasattr(vn, 'setSymbolProperties'):
                vn.setSymbolProperties(entry)
            elif vflags != 0:
                vn.setFlags(vflags & ~Varnode.typelock)
        return vn

    def newUniqueOut(self, s: int, op: PcodeOp) -> Varnode:
        """Create a new temporary output Varnode.

        C++ ref: ``Funcdata::newUniqueOut``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        ct = self._glb.types.getBase(s, TYPE_UNKNOWN) if self._glb is not None and hasattr(self._glb, 'types') else None
        vn = self._vbank.createDefUnique(s, ct, op)
        op.setOutput(vn)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, vn.getAddr())
        return vn

    def setInputVarnode(self, vn: Varnode) -> Varnode:
        """Mark a Varnode as an input to the function.

        If the Varnode is already an input, return it. Check for overlapping
        input Varnodes — if one exists with the same size and address, return
        it instead. Then set varnode properties and mark unaffected/return_address
        effects.

        C++ ref: ``Funcdata::setInputVarnode``
        """
        from ghidra.core.error import LowlevelError

        if vn.isInput():
            return vn
        invn = None
        endaddr = vn.getAddr() + vn.getSize()
        for curvn in self._vbank.beginDefFlags(Varnode.input):
            if curvn.getAddr() >= endaddr:
                break
            invn = curvn
        if invn is not None:
            if (-1 != vn.overlap(invn)) or (-1 != invn.overlap(vn)):
                if (vn.getSize() == invn.getSize()) and (vn.getAddr() == invn.getAddr()):
                    return invn
                raise LowlevelError("Overlapping input varnodes")
        vn = self._vbank.setInput(vn)
        self.setVarnodeProperties(vn)
        effecttype = self._funcp.hasEffect(vn.getAddr(), vn.getSize())
        UNAFFECTED = 1  # EffectRecord::unaffected
        RETURN_ADDRESS = 3  # EffectRecord::return_address
        if effecttype == UNAFFECTED:
            vn.setUnaffected()
        if effecttype == RETURN_ADDRESS:
            vn.setUnaffected()
            vn.setReturnAddress()
        return vn

    def deleteVarnode(self, vn: Varnode) -> None:
        self._vbank.destroy(vn)

    def findVarnodeInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findInput(s, loc)

    def findCoveredInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findCoveredInput(s, loc)

    def numVarnodes(self) -> int:
        return self._vbank.numVarnodes()

    def findVarnodeWritten(self, s, loc, pc, uniq=-1):
        effective_uniq = None if uniq == -1 else uniq
        return self._vbank.find(s, loc, pc, effective_uniq)

    def findCoveringInput(self, s, loc):
        return self._vbank.findCoveringInput(s, loc)

    def findHigh(self, nm):
        """Look up a Symbol by name and return its associated HighVariable.

        C++ ref: ``Funcdata::findHigh``
        """
        symList = []
        self._localmap.queryByName(nm, symList)
        if not symList:
            return None
        sym = symList[0]
        vn = self.findLinkedVarnode(sym.getFirstWholeMap())
        if vn is not None:
            return vn.getHigh()
        return None

    def beginLoc(self, *args):
        if not args:
            return self._vbank.beginLoc()
        if len(args) == 1:
            arg = args[0]
            if isinstance(arg, Address):
                return self._vbank.beginLocAddr(arg)
            return self._vbank.beginLocSpace(arg)
        if len(args) == 2:
            return self._vbank.beginLocSize(args[0], args[1])
        if len(args) == 3:
            if isinstance(args[2], Address):
                return self._vbank.beginLocDef(args[0], args[1], args[2])
            return self._vbank.beginLocFlags(args[0], args[1], args[2])
        if len(args) == 4:
            if not isinstance(args[2], Address):
                raise TypeError("Unsupported beginLoc overload")
            uniq = None if args[3] == -1 else args[3]
            return self._vbank.beginLocDef(args[0], args[1], args[2], uniq)
        raise TypeError("Unsupported beginLoc overload")

    def beginDef(self, *args):
        if not args:
            return self._vbank.beginDef()
        if len(args) == 1:
            return self._vbank.beginDefFlags(args[0])
        if len(args) == 2:
            return self._vbank.beginDefFlagsAddr(args[0], args[1])
        raise TypeError("Unsupported beginDef overload")

    def newVarnodeIop(self, op):
        """Create an annotation Varnode encoding a reference to a PcodeOp.

        C++ ref: ``Funcdata::newVarnodeIop``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        addr = Address(self._glb.getIopSpace(), id(op))
        ct = self._glb.types.getBase(_PTR_SIZE, TYPE_UNKNOWN)
        vn = self._vbank.create(_PTR_SIZE, addr, ct)
        vn._iop_ref = op  # Store direct reference for Python resolution
        self._iop_lookup[id(op)] = op  # Register for getOpFromConst
        PcodeOp.registerOpRef(op)
        self.assignHigh(vn)
        return vn

    def getOpFromConst(self, addr: Address):
        """Get the PcodeOp encoded in an IOP-space annotation address.

        C++ ref: ``Funcdata::getOpFromConst``
        """
        return self._iop_lookup.get(addr.getOffset())

    def newVarnodeSpace(self, spc):
        """Create a constant varnode encoding an address space identifier.

        C++ encodes the AddrSpace* pointer as a sizeof(void*)-byte constant.
        The varnode is tagged with ``setSpaceFromConst`` so that
        ``getSpaceFromConst`` returns the actual target space.

        C++ ref: ``Funcdata::newVarnodeSpace``  (funcdata_varnode.cc:190-198)
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        size = _PTR_SIZE
        ct = self._glb.types.getBase(size, TYPE_UNKNOWN)
        vn = self._vbank.create(size, Address(self._glb.getConstantSpace(), id(spc)), ct)
        vn.setSpaceFromConst(spc)
        self.assignHigh(vn)
        return vn

    def newVarnodeCallSpecs(self, fc):
        """Create an annotation Varnode encoding a reference to a FuncCallSpecs.

        C++ ref: ``Funcdata::newVarnodeCallSpecs`` — uses FSPEC space with
        the object id as the offset.
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        size = _PTR_SIZE
        addr = Address(self._glb.getFspecSpace(), id(fc))
        ct = self._glb.types.getBase(size, TYPE_UNKNOWN)
        vn = self._vbank.create(size, addr, ct)
        FuncCallSpecs.registerFspecRef(fc)
        self.assignHigh(vn)
        return vn

    def newCodeRef(self, m):
        """Create an annotation Varnode holding a code reference address.

        C++ ref: ``Funcdata::newCodeRef``
        """
        ct = self._glb.types.getTypeCode()
        vn = self._vbank.create(1, m, ct)
        vn.setFlags(Varnode.annotation)
        self.assignHigh(vn)
        return vn

    def numHeritagePasses(self, spc):
        return self._heritage.numHeritagePasses(spc)

    def deadRemovalAllowed(self, spc):
        return self._heritage.deadRemovalAllowed(spc)

    def deadRemovalAllowedSeen(self, spc):
        return self._heritage.deadRemovalAllowedSeen(spc)

    def isHeritaged(self, vn):
        return self._heritage.heritagePass(vn.getAddr()) >= 0

    def setDeadCodeDelay(self, spc, delay):
        self._heritage.setDeadCodeDelay(spc, delay)

    def getMerge(self):
        return self._covermerge

    def fillinExtrapop(self) -> int:
        """Recover extrapop from function body if unknown.

        If there is no function body or extrapop is already known, return
        the current value.  Otherwise examine the first RETURN op to
        determine the value (assumes x86 ret/ret-imm).

        C++ ref: ``Funcdata::fillinExtrapop``
        """
        from ghidra.fspec.fspec import ProtoModel

        if self.hasNoCode():
            return self._funcp.getExtraPop()

        ep = self._funcp.getExtraPop()
        if ep != ProtoModel.extrapop_unknown:
            return ep

        retop = next(self.beginOp(OpCode.CPUI_RETURN), None)
        if retop is None:
            return 0

        buf = bytearray(4)
        self._glb.loader.loadFill(buf, 4, retop.getAddr())

        extrapop = 4
        if buf[0] == 0xC2:
            extrapop = buf[2]
            extrapop <<= 8
            extrapop += buf[1]
            extrapop += 4

        self._funcp.setExtraPop(extrapop)
        return extrapop

    def isJumptableRecoveryOn(self):
        return (self._flags & Funcdata.jumptablerecovery_on) != 0

    def setJumptableRecovery(self, val):
        if val:
            self._flags &= ~Funcdata.jumptablerecovery_dont
        else:
            self._flags |= Funcdata.jumptablerecovery_dont

    def setDoublePrecisRecovery(self, val):
        if val:
            self._flags |= Funcdata.double_precis_on
        else:
            self._flags &= ~Funcdata.double_precis_on

    def isTypeRecoveryExceeded(self):
        return (self._flags & Funcdata.typerecovery_exceeded) != 0

    def setTypeRecoveryExceeded(self):
        self._flags |= Funcdata.typerecovery_exceeded

    def getCastPhaseIndex(self):
        return self._cast_phase_index

    def getHighLevelIndex(self):
        return self._high_level_index

    def getCleanUpIndex(self):
        return self._clean_up_index

    def setLanedRegGenerated(self):
        self._minLanedSize = 1000000

    def numJumpTables(self):
        return len(self._jumpvec)

    def findJumpTable(self, op):
        for jt in self._jumpvec:
            if jt.getOpAddress() == op.getAddr():
                return jt
        return None

    def removeJumpTable(self, jt):
        from ghidra.block.block import FlowBlock

        remain = []
        for curjt in self._jumpvec:
            if curjt is not jt:
                remain.append(curjt)
        op = jt.getIndirectOp()
        if op is not None:
            op.getParent().clearFlag(FlowBlock.f_switch_out)
        self._jumpvec = remain

    def linkJumpTable(self, op):
        for jt in self._jumpvec:
            if jt.getOpAddress() == op.getAddr():
                jt.setIndirectOp(op)
                return jt
        return None

    def opUnlink(self, op):
        """Unlink op from all varnodes and remove from its basic block.

        C++ ref: ``Funcdata::opUnlink``
        """
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            self.opUnsetInput(op, i)
        parent = op.getParent()
        if parent is not None:
            self.opUninsert(op)

    def opDestroyRaw(self, op):
        """Destroy a raw (dead) PcodeOp and all its unlinked varnodes.

        C++ ref: ``Funcdata::opDestroyRaw``

        Note: C++ expects inputs/outputs to be unlinked from anything else.
        We safely check before destroying each varnode.
        """
        for i in range(op.numInput()):
            self.destroyVarnode(op.getIn(i))
        outvn = op.getOut()
        if outvn is not None:
            self.destroyVarnode(outvn)
        self._obank.destroy(op)

    def opMarkHalt(self, op, flag):
        """Mark a RETURN op as a halt with the given flags.

        C++ ref: ``Funcdata::opMarkHalt``
        """
        from ghidra.core.error import LowlevelError

        if op.code() != OpCode.CPUI_RETURN:
            raise LowlevelError("Only RETURN pcode ops can be marked as halt")
        valid = (PcodeOp.halt | PcodeOp.badinstruction |
                 PcodeOp.unimplemented | PcodeOp.noreturn |
                 PcodeOp.missing)
        flag &= valid
        if flag == 0:
            raise LowlevelError("Bad halt flag")
        op.setFlag(flag)

    def opMarkStartBasic(self, op):
        op.setFlag(PcodeOp.startbasic)

    def opMarkStartInstruction(self, op):
        op.setFlag(PcodeOp.startmark)

    def opMarkNonPrinting(self, op):
        op.setFlag(PcodeOp.nonprinting)

    def opMarkNoCollapse(self, op):
        op.setFlag(PcodeOp.nocollapse)

    def opMarkCalculatedBool(self, op):
        op.setFlag(PcodeOp.calculated_bool)

    def opMarkSpacebasePtr(self, op):
        op.setFlag(PcodeOp.spacebase_ptr)

    def opClearSpacebasePtr(self, op):
        op.clearFlag(PcodeOp.spacebase_ptr)

    def opMarkSpecialPrint(self, op):
        op.setAdditionalFlag(PcodeOp.special_print)

    def opMarkCpoolTransformed(self, op):
        op.setAdditionalFlag(PcodeOp.is_cpool_transformed)

    def target(self, addr):
        return self._obank.target(addr)

    def findOp(self, sq):
        return self._obank.findOp(sq)

    def beginOp(self, opc=None):
        if opc is not None:
            return self._obank.begin(opc)
        return self._obank.beginAll()

    def beginOpAlive(self):
        return self._obank.beginAlive()

    def beginOpDead(self):
        return self._obank.beginDead()

    def beginOpAll(self):
        return self._obank.beginAll()

    def mapGlobals(self) -> None:
        """Search for addrtied Varnodes in global scope and create Symbols.

        C++ ref: ``Funcdata::mapGlobals``
        """
        from ghidra.core.error import LowlevelError
        from ghidra.types.datatype import TYPE_UNKNOWN

        inconsistentuse = False
        iter_vns = list(self._vbank.beginLoc())
        idx = 0
        uncoveredVarnodes = []
        while idx < len(iter_vns):
            vn = iter_vns[idx]
            idx += 1
            if vn.isFree():
                continue
            if not vn.isPersist():
                continue
            if vn.getSymbolEntry() is not None:
                continue
            addr = vn.getAddr()
            maxvn = vn
            endaddr = addr + vn.getSize()
            uncoveredVarnodes.clear()
            while idx < len(iter_vns):
                vn = iter_vns[idx]
                if not vn.isPersist():
                    break
                if vn.getAddr() < endaddr:
                    if vn.getAddr() != addr and vn.getSymbolEntry() is None:
                        uncoveredVarnodes.append(vn)
                    endaddr = vn.getAddr() + vn.getSize()
                    if vn.getSize() > maxvn.getSize():
                        maxvn = vn
                    idx += 1
                else:
                    break
            if maxvn.getAddr() == addr and addr + maxvn.getSize() == endaddr:
                ct = maxvn.getHigh().getType()
            else:
                ct = self._glb.types.getBase(
                    endaddr.getOffset() - addr.getOffset(),
                    TYPE_UNKNOWN,
                )
            fl_ref = [0]
            usepoint = Address()
            entry = self._localmap.queryProperties(addr, 1, usepoint, fl_ref)
            if entry is None:
                discover = self._localmap.discoverScope(addr, ct.getSize(), usepoint)
                if discover is None:
                    raise LowlevelError("Could not discover scope")
                index = 0
                nm = discover.buildVariableName(
                    addr,
                    usepoint,
                    ct,
                    index,
                    Varnode.addrtied | Varnode.persist,
                )
                discover.addSymbol(nm, ct, addr, usepoint)
            elif (addr.getOffset() + ct.getSize()) - 1 > (
                (entry.getAddr().getOffset() + entry.getSize()) - 1
            ):
                    inconsistentuse = True
                    if uncoveredVarnodes:
                        self.coverVarnodes(entry, uncoveredVarnodes)
        if inconsistentuse:
            self.warningHeader("Globals starting with '_' overlap smaller symbols at the same address")

    def prepareThisPointer(self) -> None:
        """Ensure 'this' pointer Varnode is treated as pointer data-type.

        C++ ref: ``Funcdata::prepareThisPointer``
        """
        numInputs = self._funcp.numParams()
        for i in range(numInputs):
            param = self._funcp.getParam(i)
            if param.isThisPointer() and param.isTypeLocked():
                return
        if self._localmap.hasTypeRecommendations():
            return
        dt = self._glb.types.getTypeVoid()
        spc = self._glb.getDefaultDataSpace()
        dt = self._glb.types.getTypePointer(spc.getAddrSize(), dt, spc.getWordSize())
        addr = self._funcp.getThisPointerStorage(dt)
        self._localmap.addTypeRecommendation(addr, dt)

    def markIndirectOnly(self) -> None:
        """Mark illegal input Varnodes that are only used by INDIRECT ops.

        C++ ref: ``Funcdata::markIndirectOnly``
        """
        for vn in self.beginDef(Varnode.input):
            if not vn.isIllegalInput():
                continue
            if Funcdata.checkIndirectUse(vn):
                vn.setFlags(Varnode.indirectonly)

    def setBasicBlockRange(self, bb, beg, end):
        bb.setInitialRange(beg, end)

    def clearBlocks(self):
        self._bblocks.clear()
        self._sblocks.clear()

    def clearCallSpecs(self):
        if hasattr(FuncCallSpecs, 'unregisterFspecRef'):
            for fc in self._qlst:
                FuncCallSpecs.unregisterFspecRef(fc)
        self._qlst.clear()
        self._qlst_map.clear()

    def clearJumpTables(self):
        remain = []
        for jt in self._jumpvec:
            if jt.isOverride():
                jt.clear()
                remain.append(jt)
        self._jumpvec = remain

    @staticmethod
    def compareCallspecs(a, b) -> bool:
        """Compare call specs by block index then op order.

        C++ ref: ``Funcdata::compareCallspecs``
        """
        opa = a.getOp()
        opb = b.getOp()
        ind1 = opa.getParent().getIndex()
        ind2 = opb.getParent().getIndex()
        if ind1 != ind2:
            return ind1 < ind2
        return opa.getSeqNum().getOrder() < opb.getSeqNum().getOrder()

    def sortCallSpecs(self) -> None:
        """Sort call specs in dominance order.

        Calls are put in dominance order so that earlier calls get
        evaluated first.  Order affects parameter analysis.

        C++ ref: ``Funcdata::sortCallSpecs``
        """
        import functools
        def _cmp(a, b):
            if Funcdata.compareCallspecs(a, b):
                return -1
            if Funcdata.compareCallspecs(b, a):
                return 1
            return 0
        self._qlst.sort(key=functools.cmp_to_key(_cmp))

    # --- PcodeOp creation routines ---

    def newOp(self, inputs: int, addr: Address) -> PcodeOp:
        """Create a new PcodeOp at the given address."""
        return self._obank.create(inputs, addr)

    def newOpBefore(self, op: PcodeOp, opc: OpCode, in0: Varnode,
                    in1: Varnode, in2: Optional[Varnode] = None) -> PcodeOp:
        """Create and insert a new PcodeOp before the given op.

        C++ ref: ``Funcdata::newOpBefore``
        """
        numinputs = 2 if in2 is None else 3
        newop = self.newOp(numinputs, op.getAddr())
        self.opSetOpcode(newop, opc)
        self.newUniqueOut(in0.getSize(), newop)
        self.opSetInput(newop, in0, 0)
        self.opSetInput(newop, in1, 1)
        if in2 is not None:
            self.opSetInput(newop, in2, 2)
        self.opInsertBefore(newop, op)
        return newop

    def opSetOpcode(self, op: PcodeOp, opc: OpCode) -> None:
        """Change the opcode of an existing PcodeOp.

        C++ ref: ``Funcdata::opSetOpcode``
        """
        self._obank.changeOpcode(op, self._glb.inst[opc])

    def opSetOutput(self, op: PcodeOp, vn: Varnode) -> None:
        """Set the output of a PcodeOp.

        C++ ref: ``Funcdata::opSetOutput``  (funcdata_op.cc:70-87)
        C++ calls ``vbank.setDef(vn, op)`` which triggers ``xref()`` and
        sets the ``insert`` flag — required for ``isHeritageKnown()``.
        """
        if vn is op.getOut():
            return
        old_out = op.getOut()
        if _should_log_unique_debug(op):
            _append_unique_debug_line(
                f"event=opSetOutput-begin {_format_unique_debug_op(op)} "
                f"old_out={_format_unique_debug_vn(old_out)} new_out={_format_unique_debug_vn(vn)} "
                f"{_unique_debug_caller(2)}"
            )
        if old_out is not None:
            self.opUnsetOutput(op)
        if vn.getDef() is not None:
            self.opUnsetOutput(vn.getDef())
        vn = self._vbank.setDef(vn, op)
        self.setVarnodeProperties(vn)
        op.setOutput(vn)
        if _should_log_unique_debug(op):
            _append_unique_debug_line(
                f"event=opSetOutput-end {_format_unique_debug_op(op)} new_out={_format_unique_debug_vn(vn)} "
                f"{_unique_debug_caller(2)}"
            )

    def opSetInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Set an input of a PcodeOp.

        Native Ghidra only clones constants that already have a descendant,
        because constants should generally be single-use unless they are a
        spacebase.
        """
        if vn is op.getIn(slot):
            return
        if vn.isConstant():
            if not vn.hasNoDescend():
                if not vn.isSpacebase():
                    clone = self.newConstant(vn.getSize(), vn.getOffset())
                    if hasattr(clone, 'copySymbol'):
                        clone.copySymbol(vn)
                    vn = clone
        old = op.getIn(slot)
        if old is not None:
            self.opUnsetInput(op, slot)
        vn.addDescend(op)
        op.setInput(vn, slot)

    def opSwapInput(self, op: PcodeOp, slot1: int, slot2: int) -> None:
        """Swap two inputs of a PcodeOp."""
        vn1 = op.getIn(slot1)
        vn2 = op.getIn(slot2)
        op.setInput(vn2, slot1)
        op.setInput(vn1, slot2)

    def opRemoveInput(self, op: PcodeOp, slot: int) -> None:
        """Remove an input from a PcodeOp."""
        self.opUnsetInput(op, slot)
        op.removeInput(slot)

    def opInsertInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Insert a new input into a PcodeOp at the given slot.

        Match native constant-cloning semantics from ``Funcdata::opSetInput``.
        """
        op.insertInput(slot)
        self.opSetInput(op, vn, slot)

    def opSetAllInput(self, op: PcodeOp, inputs: List[Varnode]) -> None:
        """Set all inputs of a PcodeOp at once.

        C++ ref: Funcdata::opSetAllInput in funcdata_op.cc — calls opUnsetInput
        then opSetInput for each slot, which handles constant-cloning.
        """
        for i in range(op.numInput()):
            if op.getIn(i) is not None:
                self.opUnsetInput(op, i)
        op.setNumInputs(len(inputs))
        for i, vn in enumerate(inputs):
            self.opSetInput(op, vn, i)

    def opUnsetOutput(self, op: PcodeOp) -> None:
        """Remove the output from a PcodeOp, making it free.

        C++ ref: ``Funcdata::opUnsetOutput``
        """
        out = op.getOut()
        if out is None:
            return
        if _should_log_unique_debug(op):
            _append_unique_debug_line(
                f"event=opUnsetOutput {_format_unique_debug_op(op)} old_out={_format_unique_debug_vn(out)} "
                f"{_unique_debug_caller(2)}"
            )
        op.setOutput(None)
        self._vbank.makeFree(out)
        if hasattr(out, 'clearCover'):
            out.clearCover()

    def opDestroy(self, op: PcodeOp) -> None:
        """Unlink and retire a PcodeOp, matching native ``Funcdata::opDestroy``.

        C++ ref: ``Funcdata::opDestroy``
        """
        outvn = op.getOut()
        if outvn is not None:
            self.destroyVarnode(outvn)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                self.opUnsetInput(op, i)
        parent = op.getParent()
        if parent is not None:
            self._obank.markDead(op)
            parent.removeOp(op)

    def totalReplace(self, vn, newvn) -> None:
        """Replace every read of vn with newvn.

        C++ ref: ``Funcdata::totalReplace``
        """
        for op in list(vn.beginDescend()):
            slot = op.getSlot(vn)
            self.opSetInput(op, newvn, slot)

    def totalReplaceConstant(self, vn, val: int) -> None:
        """Replace every read of vn with a constant value.

        C++ ref: ``Funcdata::totalReplaceConstant``
        """
        copyop = None
        newrep = None
        for op in list(vn.beginDescend()):
            slot = op.getSlot(vn)
            if op.isMarker():
                if copyop is None:
                    if vn.isWritten():
                        copyop = self.newOp(1, vn.getDef().getAddr())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertAfter(copyop, vn.getDef())
                    else:
                        bb = self.getBasicBlocks().getBlock(0)
                        copyop = self.newOp(1, bb.getStart())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertBegin(copyop, bb)
                else:
                    newrep = copyop.getOut()
            else:
                newrep = self.newConstant(vn.getSize(), val)
            self.opSetInput(op, newrep, slot)

    def opUnsetInput(self, op: PcodeOp, slot: int) -> None:
        """Unlink input Varnode from the given slot of a PcodeOp."""
        vn = op.getIn(slot)
        vn.eraseDescend(op)
        op.clearInput(slot)

    def opFlipCondition(self, op: PcodeOp) -> None:
        """Flip output condition of given CBRANCH."""
        op.flipFlag(PcodeOp.boolean_flip)

    def opDeadAndGone(self, op: PcodeOp) -> None:
        """Permanently destroy a previously dead PcodeOp."""
        self._obank.destroy(op)

    def opMarkAlive(self, op: PcodeOp) -> None:
        """Mark a PcodeOp as alive."""
        self._obank.markAlive(op)

    def totalNumOps(self) -> int:
        return len(list(self._obank.beginAll()))

    # --- Op flip / boolean helpers ---

    @staticmethod
    def opFlipInPlaceTest(op, fliplist: list) -> int:
        """Trace boolean to a set of PcodeOps that can flip the value.

        Returns 0 if normalizing, 1 if ambivalent, 2 if does not normalize.
        """
        opc = op.code()
        if opc == OpCode.CPUI_CBRANCH:
            vn = op.getIn(1)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            return Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
        if opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_FLOAT_EQUAL):
            fliplist.append(op)
            return 1
        if opc in (OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_FLOAT_NOTEQUAL):
            fliplist.append(op)
            return 0
        if opc in (OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS):
            vn = op.getIn(0)
            fliplist.append(op)
            if not vn.isConstant():
                return 1
            return 0
        if opc in (OpCode.CPUI_INT_SLESSEQUAL, OpCode.CPUI_INT_LESSEQUAL):
            vn = op.getIn(1)
            fliplist.append(op)
            if vn.isConstant():
                return 1
            return 0
        if opc in (OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_AND):
            vn = op.getIn(0)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            subtest1 = Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
            if subtest1 == 2:
                return 2
            vn = op.getIn(1)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            subtest2 = Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
            if subtest2 == 2:
                return 2
            fliplist.append(op)
            return subtest1
        return 2

    def opFlipInPlaceExecute(self, fliplist: list) -> None:
        """Perform op-code flips (in-place) to change a boolean value."""
        from ghidra.core.opcodes import get_booleanflip
        for op in fliplist:
            opc, flipyes = get_booleanflip(op.code())
            if opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
                otherop = op.getOut().loneDescend()
                slot = otherop.getSlot(op.getOut())
                self.opSetInput(otherop, vn, slot)
                self.opDestroy(op)
            elif opc == OpCode.CPUI_MAX:
                if op.code() == OpCode.CPUI_BOOL_AND:
                    self.opSetOpcode(op, OpCode.CPUI_BOOL_OR)
                elif op.code() == OpCode.CPUI_BOOL_OR:
                    self.opSetOpcode(op, OpCode.CPUI_BOOL_AND)
                else:
                    from ghidra.core.error import LowlevelError
                    raise LowlevelError("Bad flipInPlace op")
            else:
                self.opSetOpcode(op, opc)
                if flipyes:
                    self.opSwapInput(op, 0, 1)
                    if opc in (OpCode.CPUI_INT_LESSEQUAL, OpCode.CPUI_INT_SLESSEQUAL):
                        self.replaceLessequal(op)

    def opBoolNegate(self, vn, op, insertafter: bool):
        """Construct the boolean negation of a given boolean Varnode."""
        negateop = self.newOp(1, op.getAddr())
        self.opSetOpcode(negateop, OpCode.CPUI_BOOL_NEGATE)
        resvn = self.newUniqueOut(1, negateop)
        self.opSetInput(negateop, vn, 0)
        if insertafter:
            self.opInsertAfter(negateop, op)
        else:
            self.opInsertBefore(negateop, op)
        return resvn

    def opUndoPtradd(self, op, finalize: bool) -> None:
        """Convert a CPUI_PTRADD back into a CPUI_INT_ADD."""
        multVn = op.getIn(2)
        multSize = multVn.getOffset()
        self.opRemoveInput(op, 2)
        self.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        if multSize == 1:
            return
        offVn = op.getIn(1)
        if offVn.isConstant():
            newVal = (multSize * offVn.getOffset()) & ((1 << (offVn.getSize() * 8)) - 1)
            newOffVn = self.newConstant(offVn.getSize(), newVal)
            if finalize:
                newOffVn.updateType(offVn.getTypeReadFacing(op))
            self.opSetInput(op, newOffVn, 1)
            return
        multOp = self.newOp(2, op.getAddr())
        self.opSetOpcode(multOp, OpCode.CPUI_INT_MULT)
        addVn = self.newUniqueOut(offVn.getSize(), multOp)
        if finalize:
            addVn.updateType(multVn.getType())
            addVn.setImplied()
        self.opSetInput(multOp, offVn, 0)
        self.opSetInput(multOp, multVn, 1)
        self.opSetInput(op, addVn, 1)
        self.opInsertBefore(multOp, op)

    def createStackRef(self, spc, off, op, stackptr, insertafter: bool):
        """Create an INT_ADD PcodeOp calculating offset relative to spacebase register."""
        if stackptr is None:
            stackptr = self.newSpacebasePtr(spc)
        addrsize = stackptr.getSize()
        addop = self.newOp(2, op.getAddr())
        self.opSetOpcode(addop, OpCode.CPUI_INT_ADD)
        addout = self.newUniqueOut(addrsize, addop)
        self.opSetInput(addop, stackptr, 0)
        off = AddrSpace.byteToAddress(off, spc.getWordSize())
        self.opSetInput(addop, self.newConstant(addrsize, off), 1)
        if insertafter:
            self.opInsertAfter(addop, op)
        else:
            self.opInsertBefore(addop, op)
        return addout

    def opStackStore(self, spc, off, op, insertafter: bool):
        """Create a STORE at an offset relative to a spacebase register."""
        addout = self.createStackRef(spc, off, op, None, insertafter)
        storeop = self.newOp(3, op.getAddr())
        self.opSetOpcode(storeop, OpCode.CPUI_STORE)
        self.opSetInput(storeop, self.newVarnodeSpace(spc.getContain()), 0)
        self.opSetInput(storeop, addout, 1)
        self.opInsertAfter(storeop, addout.getDef())
        return storeop

    def opStackLoad(self, spc, off, sz: int, op, stackref, insertafter: bool):
        """Create a LOAD at an offset relative to a spacebase register."""
        addout = self.createStackRef(spc, off, op, stackref, insertafter)
        loadop = self.newOp(2, op.getAddr())
        self.opSetOpcode(loadop, OpCode.CPUI_LOAD)
        self.opSetInput(loadop, self.newVarnodeSpace(spc.getContain()), 0)
        self.opSetInput(loadop, addout, 1)
        res = self.newUniqueOut(sz, loadop)
        self.opInsertAfter(loadop, addout.getDef())
        return res

    # --- CSE / transform helpers ---

    @staticmethod
    def cseFindInBlock(op, vn, bl, earliest):
        """Find a duplicate calculation of op reading vn in block bl before earliest."""
        from ghidra.core.expression import functionalEqualityLevel

        for desc in vn.getDescendants():
            if desc is op:
                continue
            if desc.getParent() is not bl:
                continue
            if earliest is not None:
                if earliest.getSeqNum().getOrder() < desc.getSeqNum().getOrder():
                    continue
            outvn1 = op.getOut()
            outvn2 = desc.getOut()
            if outvn2 is None:
                continue
            buf1 = [None, None]
            buf2 = [None, None]
            if functionalEqualityLevel(outvn1, outvn2, buf1, buf2) == 0:
                return desc
        return None

    def cseElimination(self, op1, op2):
        """Perform a Common Subexpression Elimination step between two ops."""
        from ghidra.block.block import FlowBlock
        if op1.getParent() is op2.getParent():
            if op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder():
                replace = op1
            else:
                replace = op2
        else:
            common = FlowBlock.findCommonBlock(op1.getParent(), op2.getParent())
            if common is op1.getParent():
                replace = op1
            elif common is op2.getParent():
                replace = op2
            else:
                replace = self.newOp(op1.numInput(), common.getStop())
                self.opSetOpcode(replace, op1.code())
                self.newVarnodeOut(op1.getOut().getSize(), op1.getOut().getAddr(), replace)
                for i in range(op1.numInput()):
                    inv = op1.getIn(i)
                    if inv.isConstant():
                        self.opSetInput(replace, self.newConstant(inv.getSize(), inv.getOffset()), i)
                    else:
                        self.opSetInput(replace, inv, i)
                self.opInsertEnd(replace, common)
        if replace is not op1:
            self.totalReplace(op1.getOut(), replace.getOut())
            self.opDestroy(op1)
        if replace is not op2:
            self.totalReplace(op2.getOut(), replace.getOut())
            self.opDestroy(op2)
        return replace

    def cseEliminateList(self, hashlist: list, outlist: list) -> None:
        """Perform CSE on a list of (hash, PcodeOp) pairs."""
        if not hashlist:
            return
        hashlist.sort(key=lambda x: x[0])
        for i in range(len(hashlist) - 1):
            if hashlist[i][0] == hashlist[i + 1][0]:
                op1 = hashlist[i][1]
                op2 = hashlist[i + 1][1]
                if not op1.isDead() and not op2.isDead() and op1.isCseMatch(op2):
                    outvn1 = op1.getOut()
                    outvn2 = op2.getOut()
                    if (outvn1 is None or self.isHeritaged(outvn1)) and (
                        outvn2 is None or self.isHeritaged(outvn2)
                    ):
                        resop = self.cseElimination(op1, op2)
                        outlist.append(resop.getOut())

    def replaceLessequal(self, op) -> bool:
        """Replace INT_LESSEQUAL/INT_SLESSEQUAL with strict less-than."""
        vn = op.getIn(0)
        if vn.isConstant():
            diff = -1
            i = 0
        else:
            vn = op.getIn(1)
            if vn.isConstant():
                diff = 1
                i = 1
            else:
                return False
        mask = (1 << (vn.getSize() * 8)) - 1
        half = 1 << (vn.getSize() * 8 - 1)
        val = vn.getOffset()
        if val >= half:
            val = val - (mask + 1)
        if op.code() == OpCode.CPUI_INT_SLESSEQUAL:
            if diff == -1 and val == -(1 << 63):
                return False
            if diff == 1 and val == ((1 << 63) - 1):
                return False
            if val < 0 and val + diff > 0:
                return False
            if val > 0 and val + diff < 0:
                return False
            self.opSetOpcode(op, OpCode.CPUI_INT_SLESS)
        else:
            if diff == -1 and val == 0:
                return False
            if diff == 1 and (vn.getOffset() == mask):
                return False
            self.opSetOpcode(op, OpCode.CPUI_INT_LESS)
        res = (val + diff) & mask
        newvn = self.newConstant(vn.getSize(), res)
        if hasattr(newvn, "copySymbol"):
            newvn.copySymbol(vn)
        self.opSetInput(op, newvn, i)
        return True

    def distributeIntMultAdd(self, op) -> bool:
        """Distribute constant coefficient to additive input."""
        addop = op.getIn(0).getDef()
        vn0 = addop.getIn(0)
        vn1 = addop.getIn(1)
        if vn0.isFree() and not vn0.isConstant():
            return False
        if vn1.isFree() and not vn1.isConstant():
            return False
        coeff = op.getIn(1).getOffset()
        sz = op.getOut().getSize()
        mask = (1 << (sz * 8)) - 1
        if vn0.isConstant():
            newvn0 = self.newConstant(sz, (coeff * vn0.getOffset()) & mask)
        else:
            newop0 = self.newOp(2, op.getAddr())
            self.opSetOpcode(newop0, OpCode.CPUI_INT_MULT)
            newvn0 = self.newUniqueOut(sz, newop0)
            self.opSetInput(newop0, vn0, 0)
            self.opSetInput(newop0, self.newConstant(sz, coeff), 1)
            self.opInsertBefore(newop0, op)
        if vn1.isConstant():
            newvn1 = self.newConstant(sz, (coeff * vn1.getOffset()) & mask)
        else:
            newop1 = self.newOp(2, op.getAddr())
            self.opSetOpcode(newop1, OpCode.CPUI_INT_MULT)
            newvn1 = self.newUniqueOut(sz, newop1)
            self.opSetInput(newop1, vn1, 0)
            self.opSetInput(newop1, self.newConstant(sz, coeff), 1)
            self.opInsertBefore(newop1, op)
        self.opSetInput(op, newvn0, 0)
        self.opSetInput(op, newvn1, 1)
        self.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        return True

    def collapseIntMultMult(self, vn) -> bool:
        """Collapse constant coefficients for two chained CPUI_INT_MULT."""
        if not vn.isWritten():
            return False
        op = vn.getDef()
        if op.code() != OpCode.CPUI_INT_MULT:
            return False
        constFirst = op.getIn(1)
        if not constFirst.isConstant():
            return False
        if not op.getIn(0).isWritten():
            return False
        otherOp = op.getIn(0).getDef()
        if otherOp.code() != OpCode.CPUI_INT_MULT:
            return False
        constSecond = otherOp.getIn(1)
        if not constSecond.isConstant():
            return False
        invn = otherOp.getIn(0)
        if invn.isFree():
            return False
        sz = invn.getSize()
        mask = (1 << (sz * 8)) - 1
        val = (constFirst.getOffset() * constSecond.getOffset()) & mask
        self.opSetInput(op, self.newConstant(sz, val), 1)
        self.opSetInput(op, invn, 0)
        return True

    def buildCopyTemp(self, vn, point):
        """Create a COPY of given Varnode in a temporary register."""
        from ghidra.block.block import FlowBlock
        otherOp = None
        usedCopy = None
        for desc in vn.getDescendants():
            if desc.code() != OpCode.CPUI_COPY:
                continue
            outvn = desc.getOut()
            if outvn.getSpace().getType() == IPTR_INTERNAL:
                if not outvn.isTypeLock():
                    otherOp = desc
                    break
        if otherOp is not None:
            if point.getParent() is otherOp.getParent():
                if point.getSeqNum().getOrder() < otherOp.getSeqNum().getOrder():
                    usedCopy = None
                else:
                    usedCopy = otherOp
            else:
                common = FlowBlock.findCommonBlock(point.getParent(), otherOp.getParent())
                if common is point.getParent():
                    usedCopy = None
                elif common is otherOp.getParent():
                    usedCopy = otherOp
                else:
                    usedCopy = self.newOp(1, common.getStop())
                    self.opSetOpcode(usedCopy, OpCode.CPUI_COPY)
                    self.newUniqueOut(vn.getSize(), usedCopy)
                    self.opSetInput(usedCopy, vn, 0)
                    self.opInsertEnd(usedCopy, common)
        if usedCopy is None:
            usedCopy = self.newOp(1, point.getAddr())
            self.opSetOpcode(usedCopy, OpCode.CPUI_COPY)
            self.newUniqueOut(vn.getSize(), usedCopy)
            self.opSetInput(usedCopy, vn, 0)
            self.opInsertBefore(usedCopy, point)
        if otherOp is not None and otherOp is not usedCopy:
            self.totalReplace(otherOp.getOut(), usedCopy.getOut())
            self.opDestroy(otherOp)
        return usedCopy.getOut()

    # --- Block manipulation helpers ---

    def pushMultiequals(self, bb) -> None:
        """Push MULTIEQUAL Varnodes from bb into its output block."""
        if bb.sizeOut() == 0:
            return
        if bb.sizeOut() > 1:
            self.warningHeader("push_multiequal on block with multiple outputs")
        outblock = bb.getOut(0)
        outblock_ind = bb.getOutRevIndex(0)
        for op in list(bb.getOpList()):
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            origvn = op.getOut()
            if origvn.hasNoDescend():
                continue
            needreplace = False
            neednewunique = False
            for desc in origvn.getDescendants():
                if desc.code() == OpCode.CPUI_MULTIEQUAL and desc.getParent() is outblock:
                    deadEdge = True
                    for i in range(desc.numInput()):
                        if i == outblock_ind:
                            continue
                        if desc.getIn(i) is origvn:
                            deadEdge = False
                            break
                    if deadEdge:
                        if origvn.getAddr() == desc.getOut().getAddr() and origvn.isAddrTied():
                            neednewunique = True
                        continue
                needreplace = True
                break
            if not needreplace:
                continue
            branches = []
            if neednewunique:
                replacevn = self.newUnique(origvn.getSize())
            else:
                replacevn = self.newVarnode(origvn.getSize(), origvn.getAddr())
            for i in range(outblock.sizeIn()):
                if outblock.getIn(i) is bb:
                    branches.append(origvn)
                else:
                    branches.append(replacevn)
            replaceop = self.newOp(len(branches), outblock.getStart())
            self.opSetOpcode(replaceop, OpCode.CPUI_MULTIEQUAL)
            self.opSetOutput(replaceop, replacevn)
            self.opSetAllInput(replaceop, branches)
            self.opInsertBegin(replaceop, outblock)
            for desc in list(origvn.getDescendants()):
                for i in range(desc.numInput()):
                    if desc.getIn(i) is not origvn:
                        continue
                    if i == outblock_ind and desc.getParent() is outblock and desc.code() == OpCode.CPUI_MULTIEQUAL:
                        continue
                    self.opSetInput(desc, replacevn, i)
                    break

    def nodeSplitBlockEdge(self, b, inedge):
        """Split a basic block along an in edge, returning the new copy."""
        a = b.getIn(inedge)
        bprime = self._bblocks.newBlockBasic(self)
        bprime.setFlag(FlowBlock.f_duplicate_block)
        bprime.copyRange(b)
        self._bblocks.switchEdge(a, b, bprime)
        i = 0
        while i < b.sizeOut():
            self._bblocks.addEdge(bprime, b.getOut(i))
            i += 1
        return bprime

    def nodeSplit(self, b, inedge: int) -> None:
        """Split control-flow into a basic block, duplicating p-code into a new block."""
        from ghidra.core.error import LowlevelError

        if b.sizeOut() != 0:
            raise LowlevelError("Cannot (currently) nodesplit block with out flow")
        if b.sizeIn() <= 1:
            raise LowlevelError("Cannot nodesplit block with only 1 in edge")
        for i in range(b.sizeIn()):
            if b.getIn(i).isMark():
                raise LowlevelError("Cannot nodesplit block with redundant in edges")
            b.setMark()
        for i in range(b.sizeIn()):
            b.clearMark()
        bprime = self.nodeSplitBlockEdge(b, inedge)
        cloner = CloneBlockOps(self)
        cloner.cloneBlock(b, bprime, inedge)
        self.structureReset()

    def pushBranch(self, bb, slot: int, bbnew) -> None:
        """Move a control-flow edge from one block to another (for switch guard elimination)."""
        from ghidra.core.error import LowlevelError

        cbranch = bb.lastOp()
        if cbranch.code() != OpCode.CPUI_CBRANCH or bb.sizeOut() != 2:
            raise LowlevelError("Cannot push non-conditional edge")
        indop = bbnew.lastOp()
        if indop.code() != OpCode.CPUI_BRANCHIND:
            raise LowlevelError("Can only push branch into indirect jump")
        self.opRemoveInput(cbranch, 1)
        self.opSetOpcode(cbranch, OpCode.CPUI_BRANCH)
        self._bblocks.moveOutEdge(bb, slot, bbnew)
        self.structureReset()

    def forceGoto(self, pcop, pcdest) -> bool:
        """Force a specific control-flow edge to be marked as unstructured."""
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            op = bl.lastOp()
            if op is None:
                continue
            if op.getAddr() != pcop:
                continue
            for j in range(bl.sizeOut()):
                bl2 = bl.getOut(j)
                op2 = bl2.lastOp()
                if op2 is None:
                    continue
                if op2.getAddr() != pcdest:
                    continue
                bl.setGotoBranch(j)
                return True
        return False

    def removeFromFlowSplit(self, bl, swap: bool) -> None:
        """Remove a basic block splitting its control-flow into two distinct paths."""
        from ghidra.core.error import LowlevelError

        if not bl.emptyOp():
            raise LowlevelError("Can only split the flow for an empty block")
        self._bblocks.removeFromFlowSplit(bl, swap)
        self._bblocks.removeBlock(bl)
        self.structureReset()

    def switchEdge(self, inblock, outbefore, outafter) -> None:
        """Switch an outgoing edge from source block to flow into another block."""
        self._bblocks.switchEdge(inblock, outbefore, outafter)
        self.structureReset()

    def nodeJoinCreateBlock(self, block1, block2, exita, exitb,
                            fora_block1ishigh: bool, forb_block1ishigh: bool,
                            addr) -> 'BlockBasic':
        """Create a new basic block for holding a merged CBRANCH."""
        from ghidra.block.block import FlowBlock
        newblock = self._bblocks.newBlockBasic(self)
        newblock.setFlag(FlowBlock.f_joined_block)
        newblock.setInitialRange(addr, addr)
        if fora_block1ishigh:
            self._bblocks.removeEdge(block1, exita)
            swapa = block2
        else:
            self._bblocks.removeEdge(block2, exita)
            swapa = block1
        if forb_block1ishigh:
            self._bblocks.removeEdge(block1, exitb)
            swapb = block2
        else:
            self._bblocks.removeEdge(block2, exitb)
            swapb = block1
        self._bblocks.moveOutEdge(swapa, swapa.getOutIndex(exita), newblock)
        self._bblocks.moveOutEdge(swapb, swapb.getOutIndex(exitb), newblock)
        self._bblocks.addEdge(block1, newblock)
        self._bblocks.addEdge(block2, newblock)
        self.structureReset()
        return newblock

    def installSwitchDefaults(self) -> None:
        """Make sure default switch cases are properly labeled."""
        for jt in self._jumpvec:
            indop = jt.getIndirectOp()
            ind = indop.getParent()
            if jt.getDefaultBlock() != -1:
                ind.setDefaultSwitch(jt.getDefaultBlock())

    @staticmethod
    def descendantsOutside(vn) -> bool:
        """Return True if any PcodeOp reading vn is in a non-dead block."""
        for desc in vn.beginDescend():
            if not desc.getParent().isDead():
                return True
        return False

    @staticmethod
    def findPrimaryBranch(ops, findbranch: bool, findcall: bool, findreturn: bool):
        """Find the primary branch op from a list of ops."""
        for op in ops:
            opc = op.code()
            if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
                if findbranch:
                    if not op.getIn(0).isConstant():
                        return op
            elif opc == OpCode.CPUI_BRANCHIND:
                if findbranch:
                    return op
            elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                if findcall:
                    return op
            elif opc == OpCode.CPUI_RETURN:
                if findreturn:
                    return op
        return None

    @staticmethod
    def checkIndirectUse(vn) -> bool:
        """Check if the given Varnode only flows into call-based INDIRECT ops.

        Flow is followed through MULTIEQUAL ops and INDIRECT store ops.

        C++ ref: ``Funcdata::checkIndirectUse``
        """
        vlist = [vn]
        vn.setMark()
        result = True
        i = 0
        while i < len(vlist) and result:
            cur = vlist[i]
            i += 1
            for op in cur.beginDescend():
                opc = op.code()
                if opc == OpCode.CPUI_INDIRECT:
                    if op.isIndirectStore():
                        outvn = op.getOut()
                        if not outvn.isMark():
                            vlist.append(outvn)
                            outvn.setMark()
                elif opc == OpCode.CPUI_MULTIEQUAL:
                    outvn = op.getOut()
                    if not outvn.isMark():
                        vlist.append(outvn)
                        outvn.setMark()
                else:
                    result = False
                    break
        for marked_vn in vlist:
            marked_vn.clearMark()
        return result

    # --- Varnode manipulation helpers ---

    def destroyVarnode(self, vn) -> None:
        """Delete the given Varnode, clearing all references first.

        All PcodeOps reading the Varnode have their input slot cleared.
        If the Varnode is defined by a PcodeOp, that op's output is cleared.

        C++ ref: ``Funcdata::destroyVarnode``
        """
        for op in vn.getDescendants():
            slot = op.getSlot(vn)
            op.clearInput(slot)
        defop = vn.getDef()
        if defop is not None:
            defop.setOutput(None)
            vn._def = None
        vn.destroyDescend()
        self._vbank.destroy(vn)

    def cloneVarnode(self, vn):
        """Clone a Varnode, preserving allowed flags.

        C++ ref: ``Funcdata::cloneVarnode``
        """
        ct = vn.getType() if hasattr(vn, 'getType') else None
        newvn = self._vbank.create(vn.getSize(), vn.getAddr(), ct)
        # Clone only the allowed flags
        allowed = (Varnode.annotation | Varnode.externref |
                   Varnode.readonly | Varnode.persist |
                   Varnode.addrtied | Varnode.addrforce |
                   Varnode.indirect_creation | Varnode.incidental_copy |
                   Varnode.volatil | Varnode.mapped)
        vflags = vn.getFlags() & allowed
        newvn.setFlags(vflags)
        # Preserve space-from-const reference for LOAD/STORE space constants
        space_ref = vn._space_ref
        if space_ref is not None:
            newvn._space_ref = space_ref
        return newvn

    def splitUses(self, vn) -> None:
        """Duplicate the defining PcodeOp at each read so each becomes a new unique.

        For each descendant, clone the defining op and create a new output
        Varnode, then redirect the descendant's input to the new clone
        output. Dead-code actions should remove the original op after all
        descendants have been rewritten.

        C++ ref: ``Funcdata::splitUses``
        """
        op = vn.getDef()
        if op is None:
            return
        descs = list(vn.getDescendants())
        if len(descs) <= 1:
            return
        for useop in descs:
            slot = useop.getSlot(vn)
            newop = self.newOp(op.numInput(), op.getAddr())
            newvn = self.newVarnode(vn.getSize(), vn.getAddr(), vn.getType() if hasattr(vn, 'getType') else None)
            self.opSetOutput(newop, newvn)
            self.opSetOpcode(newop, op.code())
            for i in range(op.numInput()):
                self.opSetInput(newop, op.getIn(i), i)
            self.opSetInput(useop, newvn, slot)
            self.opInsertBefore(newop, op)

    def descend2Undef(self, vn) -> bool:
        """Replace reads of the given Varnode with a special 0xBADDEF constant.

        For MULTIEQUAL and INDIRECT ops, a COPY is inserted since constants
        cannot be placed directly as inputs. Blocks with no predecessors
        (unreachable) are skipped.

        C++ ref: ``Funcdata::descend2Undef``
        """
        res = False
        sz = vn.getSize()
        for op in list(vn.getDescendants()):
            bl = op.getParent()
            if bl is not None and hasattr(bl, 'isDead') and bl.isDead():
                continue
            if bl is not None and bl.sizeIn() != 0:
                res = True
            i = op.getSlot(vn)
            badconst = self.newConstant(sz, 0xBADDEF)
            opc = op.code()
            if opc == OpCode.CPUI_MULTIEQUAL:
                # Cannot put constant directly into MULTIEQUAL
                inbl = bl.getIn(i) if bl is not None else None
                if inbl is not None:
                    copyop = self.newOp(1, inbl.getStart())
                    inputvn = self.newUniqueOut(sz, copyop)
                    self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                    self.opSetInput(copyop, badconst, 0)
                    self.opInsertEnd(copyop, inbl)
                    self.opSetInput(op, inputvn, i)
                else:
                    self.opSetInput(op, badconst, i)
            elif opc == OpCode.CPUI_INDIRECT:
                # Cannot put constant directly into INDIRECT
                copyop = self.newOp(1, op.getAddr())
                inputvn = self.newUniqueOut(sz, copyop)
                self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                self.opSetInput(copyop, badconst, 0)
                self.opInsertBefore(copyop, op)
                self.opSetInput(op, inputvn, i)
            else:
                self.opSetInput(op, badconst, i)
        return res

    def assignHigh(self, vn):
        """Assign a HighVariable to a Varnode if high-level analysis is on.

        Only assigns if highlevel_on flag is set. Calculates cover if the
        Varnode already has one, and skips annotation Varnodes.

        C++ ref: ``Funcdata::assignHigh``
        """
        if (self._flags & Funcdata.highlevel_on) != 0:
            if vn.hasCover():
                vn.calcCover()
            if not vn.isAnnotation():
                return HighVariable(vn)
        return None

    def setVarnodeProperties(self, vn) -> None:
        """Look-up boolean properties and data-type information for a Varnode.

        C++ ref: ``Funcdata::setVarnodeProperties``
        """
        if not vn.isMapped():
            vflags_ref = [0]
            usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else Address()
            entry = None
            if self._localmap is not None and hasattr(self._localmap, 'queryProperties'):
                entry = self._localmap.queryProperties(vn.getAddr(), vn.getSize(), usepoint, vflags_ref)
            vflags = vflags_ref[0]
            if entry is not None and hasattr(vn, 'setSymbolProperties'):
                vn.setSymbolProperties(entry)
            elif hasattr(vn, 'setFlags'):
                vn.setFlags(vflags & ~Varnode.typelock)
        if getattr(vn, '_cover', None) is None:
            if self.isHighOn() and hasattr(vn, 'calcCover'):
                vn.calcCover()

    def coverVarnodes(self, entry, vnlist: list) -> None:
        """Make sure every Varnode in the given list has a Symbol it will link to.

        This is used when Varnodes overlap a locked Symbol but extend beyond it.
        An existing Symbol is passed in with a list of possibly overextending
        Varnodes. The list is in Address order. We check that each Varnode has
        a Symbol that overlaps its first byte (to guarantee a link). If one
        doesn't exist it is created.

        C++ ref: ``Funcdata::coverVarnodes``
        """
        sym = entry.getSymbol()
        scope = sym.getScope()
        for i, vn in enumerate(vnlist):
            # We only need to check once for all Varnodes at the same Address
            # Of these, pick the biggest Varnode (last one in the list at same addr)
            if i + 1 < len(vnlist) and vnlist[i + 1].getAddr() == vn.getAddr():
                continue
            usepoint = vn.getUsePoint(self)
            overlap_entry = scope.findContainer(vn.getAddr(), vn.getSize(), usepoint)
            if overlap_entry is None:
                diff = vn.getOffset() - entry.getAddr().getOffset()
                name = f"{sym.getName()}_{diff}"
                if vn.isAddrTied():
                    usepoint = Address()
                scope.addSymbol(name, vn.getHigh().getType(), vn.getAddr(), usepoint)

    def syncVarnodesWithSymbol(self, iterobj, fl: int, ct) -> bool:
        """Update boolean properties and data-type on a set of Varnodes.

        The iterator provides a sequence of Varnodes at the same location.
        We update their flags and optionally their data-type to match what
        is dictated by the Symbol mapping.

        C++ ref: ``Funcdata::syncVarnodesWithSymbol``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        updateoccurred = False
        mask = VnCls.mapped
        if (fl & VnCls.addrtied) == 0:
            mask |= VnCls.addrtied | VnCls.addrforce
        if (fl & VnCls.nolocalalias) != 0:
            mask |= VnCls.nolocalalias | VnCls.addrforce
        fl &= mask

        vnlist = list(iterobj) if not isinstance(iterobj, list) else iterobj
        _sync_debug_group_log(vnlist, f"sync_group_enter mask={mask:#x} fl={fl:#x}")
        for vn in vnlist:
            if vn.isFree():
                continue
            vnflags = vn.getFlags()
            mapentry = vn.getSymbolEntry() if hasattr(vn, 'getSymbolEntry') else getattr(vn, '_mapentry', None)
            if mapentry is not None:
                localMask = mask & ~VnCls.mapped
                localFlags = fl & localMask
                if (vnflags & localMask) != localFlags:
                    updateoccurred = True
                    _sync_debug_log(
                        vn,
                        f"sync_member_update path=mapentry old={vnflags:#x} "
                        f"mask={localMask:#x} new={localFlags:#x}",
                    )
                    vn.setFlags(localFlags)
                    vn.clearFlags((~localFlags) & localMask)
            elif (vnflags & mask) != fl:
                updateoccurred = True
                _sync_debug_log(
                    vn,
                    f"sync_member_update path=nomap old={vnflags:#x} "
                    f"mask={mask:#x} new={fl:#x}",
                )
                vn.setFlags(fl)
                vn.clearFlags((~fl) & mask)
            if ct is not None and hasattr(vn, 'updateType'):
                old_type = vn.getType() if hasattr(vn, 'getType') else None
                if vn.updateType(ct):
                    updateoccurred = True
                    old_name = old_type.getName() if old_type is not None and hasattr(old_type, 'getName') else str(old_type)
                    new_name = ct.getName() if hasattr(ct, 'getName') else str(ct)
                    old_meta = old_type.getMetatype() if old_type is not None and hasattr(old_type, 'getMetatype') else None
                    new_meta = ct.getMetatype() if hasattr(ct, 'getMetatype') else None
                    old_size = old_type.getSize() if old_type is not None and hasattr(old_type, 'getSize') else None
                    new_size = ct.getSize() if hasattr(ct, 'getSize') else None
                    _sync_debug_log(
                        vn,
                        "sync_member_update type=1 "
                        f"old={old_name}:{old_meta}:{old_size}:id={id(old_type) if old_type is not None else 0} "
                        f"new={new_name}:{new_meta}:{new_size}:id={id(ct)}",
                    )
        _sync_debug_group_log(vnlist, f"sync_group_exit changed={int(updateoccurred)}")
        return updateoccurred

    def handleSymbolConflict(self, entry, vn):
        """Handle a Varnode that overlaps the given SymbolEntry.

        Make sure the Varnode is part of the variable underlying the Symbol.
        If not, remap things so that the Varnode maps to a distinct Symbol.
        In either case, attach the appropriate Symbol to the Varnode.

        C++ ref: ``Funcdata::handleSymbolConflict``
        """
        if entry is None:
            return None
        # Simple cases: input, addrtied, persist, constant, or dynamic entry
        if vn.isInput() or vn.isAddrTied() or vn.isPersist() or vn.isConstant() or \
           (hasattr(entry, 'isDynamic') and entry.isDynamic()):
            vn.setSymbolEntry(entry)
            return entry.getSymbol() if hasattr(entry, 'getSymbol') else None

        high = vn.getHigh()
        otherHigh = None
        # Look for a conflicting HighVariable at same size/addr using O(K) index
        eaddr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        esz = entry.getSize() if hasattr(entry, 'getSize') else None
        if eaddr is not None and esz is not None and self._vbank is not None and hasattr(self._vbank, 'findLoc'):
            for othervn in self._vbank.findLoc(eaddr, esz):
                tmpHigh = othervn.getHigh() if hasattr(othervn, 'getHigh') else None
                if tmpHigh is not high:
                    otherHigh = tmpHigh
                    break

        if otherHigh is None:
            vn.setSymbolEntry(entry)
            return entry.getSymbol() if hasattr(entry, 'getSymbol') else None

        # Conflicting variable - build a dynamic symbol
        self.buildDynamicSymbol(vn)
        se = vn.getSymbolEntry()
        return se.getSymbol() if se is not None and hasattr(se, 'getSymbol') else None

    def applyUnionFacet(self, entry, dhash) -> bool:
        """Apply union facet resolution from a dynamic hash.

        The SymbolEntry encodes a UnionFacetSymbol which selects a specific
        field of a union data-type to apply at a particular PcodeOp edge.

        C++ ref: ``Funcdata::applyUnionFacet``
        """
        sym = entry.getSymbol()
        op = dhash.findOp(self, entry.getFirstUseAddress(), entry.getHash())
        if op is None:
            return False
        from ghidra.analysis.dynamic import DynamicHash
        from ghidra.types.resolve import ResolvedUnion

        slot = DynamicHash.getSlotFromHash(entry.getHash())
        fldNum = sym.getFieldNumber()
        resolve = ResolvedUnion(sym.getType(), fldNum, self._glb.types)
        resolve.setLock(True)
        return self.setUnionField(sym.getType(), op, slot, resolve)

    def onlyOpUse(self, invn, opmatch, trial, mainFlags) -> bool:
        """Check if a Varnode is only used as a parameter to a given op.

        Walk all descendants of invn. If every path leads to opmatch
        (at the correct slot) or to an INDIRECT / MULTIEQUAL / extension,
        return True. Any other real use means the Varnode is not exclusively
        used for parameter passing.

        C++ ref: ``Funcdata::onlyOpUse``
        """
        from ghidra.analysis.ancestor import TraverseNode

        invn.setMark()
        varlist = [TraverseNode(invn, mainFlags)]
        res = True
        i = 0
        _paramuse_debug_log(
            opmatch,
            trial,
            "onlyOpUse:start "
            f"invn={invn.getAddr().getOffset():#x}:{invn.getSize()} "
            f"mainFlags={mainFlags:#x} "
            f"written={int(invn.isWritten())} "
            f"input={int(invn.isInput())} "
            f"typelock={int(invn.isTypeLock())} "
            f"directwrite={int(invn.isDirectWrite())} "
            f"def={invn.getDef().code().name + '@' + hex(invn.getDef().getAddr().getOffset()) if invn.isWritten() else 'None'}",
        )
        while i < len(varlist) and res:
            traversenode = varlist[i]
            i += 1
            vn = traversenode.vn
            baseFlags = traversenode.flags
            _paramuse_debug_log(
                opmatch,
                trial,
                "onlyOpUse:visit "
                f"vn={vn.getAddr().getOffset():#x}:{vn.getSize()} "
                f"baseFlags={baseFlags:#x}",
            )
            for op in vn.getDescend():
                if op is opmatch:
                    if op.getIn(trial.getSlot()) is vn:
                        _paramuse_debug_log(
                            opmatch,
                            trial,
                            "onlyOpUse:skip-opmatch "
                            f"op={op.code().name}@{op.getAddr().getOffset():#x}",
                        )
                        continue
                curFlags = baseFlags
                opc = op.code()
                debug_action = "continue"
                if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH,
                           OpCode.CPUI_BRANCHIND, OpCode.CPUI_LOAD, OpCode.CPUI_STORE):
                    debug_action = "fail-memory-use"
                    res = False
                    break
                elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                    debug_action = "call-doubleuse"
                    if self.checkCallDoubleUse(opmatch, op, vn, curFlags, trial):
                        _paramuse_debug_log(
                            opmatch,
                            trial,
                            "onlyOpUse:call-ok "
                            f"op={op.code().name}@{op.getAddr().getOffset():#x} "
                            f"vn={vn.getAddr().getOffset():#x}:{vn.getSize()} "
                            f"flags={curFlags:#x}",
                        )
                        continue
                    debug_action = "fail-call"
                    res = False
                    break
                elif opc == OpCode.CPUI_INDIRECT:
                    curFlags |= TraverseNode.indirectalt
                    debug_action = "mark-indirectalt"
                elif opc == OpCode.CPUI_COPY:
                    outvn = op.getOut()
                    if outvn is not None and outvn.getSpace().getType() != IPTR_INTERNAL:
                        if (not op.isIncidentalCopy()) and (not vn.isIncidentalCopy()):
                            curFlags |= TraverseNode.actionalt
                            debug_action = "mark-actionalt"
                elif opc == OpCode.CPUI_RETURN:
                    if opmatch.code() == OpCode.CPUI_RETURN:
                        if op.getIn(trial.getSlot()) is vn:
                            _paramuse_debug_log(
                                opmatch,
                                trial,
                                "onlyOpUse:return-same-slot "
                                f"op={op.getAddr().getOffset():#x}",
                            )
                            continue
                    elif self._activeoutput is not None:
                        if op.getIn(0) is not vn:
                            if not TraverseNode.isAlternatePathValid(vn, curFlags):
                                _paramuse_debug_log(
                                    opmatch,
                                    trial,
                                    "onlyOpUse:return-ignore "
                                    f"op={op.getAddr().getOffset():#x} "
                                    f"flags={curFlags:#x}",
                                )
                                continue
                    debug_action = "fail-return"
                    res = False
                    break
                elif opc in (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_SEXT,
                             OpCode.CPUI_INT_ZEXT, OpCode.CPUI_CAST):
                    debug_action = "pass-through"
                elif opc == OpCode.CPUI_PIECE:
                    if op.getIn(0) is vn:
                        if (curFlags & TraverseNode.lsb_truncated) != 0:
                            _paramuse_debug_log(
                                opmatch,
                                trial,
                                "onlyOpUse:piece-ignore "
                                f"op={op.getAddr().getOffset():#x} "
                                f"flags={curFlags:#x}",
                            )
                            continue
                        curFlags |= TraverseNode.concat_high
                        debug_action = "mark-concat-high"
                elif opc == OpCode.CPUI_SUBPIECE:
                    if op.getIn(1).getOffset() != 0:
                        if (curFlags & TraverseNode.concat_high) == 0:
                            curFlags |= TraverseNode.lsb_truncated
                            debug_action = "mark-lsb-truncated"
                else:
                    curFlags |= TraverseNode.actionalt
                    debug_action = "mark-actionalt-default"
                subvn = op.getOut()
                _paramuse_debug_log(
                    opmatch,
                    trial,
                    "onlyOpUse:desc "
                    f"op={opc.name}@{op.getAddr().getOffset():#x} "
                    f"vn={vn.getAddr().getOffset():#x}:{vn.getSize()} "
                    f"action={debug_action} flags={curFlags:#x} "
                    f"out={subvn.getAddr().getOffset():#x}:{subvn.getSize()}" if subvn is not None else
                    "onlyOpUse:desc "
                    f"op={opc.name}@{op.getAddr().getOffset():#x} "
                    f"vn={vn.getAddr().getOffset():#x}:{vn.getSize()} "
                    f"action={debug_action} flags={curFlags:#x} out=None",
                )
                if subvn is not None:
                    if subvn.isPersist():
                        _paramuse_debug_log(
                            opmatch,
                            trial,
                            "onlyOpUse:fail-persist "
                            f"out={subvn.getAddr().getOffset():#x}:{subvn.getSize()}",
                        )
                        res = False
                        break
                    if not subvn.isMark():
                        varlist.append(TraverseNode(subvn, curFlags))
                        subvn.setMark()
                        _paramuse_debug_log(
                            opmatch,
                            trial,
                            "onlyOpUse:enqueue "
                            f"out={subvn.getAddr().getOffset():#x}:{subvn.getSize()} "
                            f"flags={curFlags:#x}",
                        )
        for traversenode in varlist:
            traversenode.vn.clearMark()
        _paramuse_debug_log(opmatch, trial, f"onlyOpUse:end result={int(res)}")
        return res

    def ancestorOpUse(self, maxlevel: int, invn, op, trial, offset: int, mainFlags: int) -> bool:
        """Test if the given trial Varnode is likely only used for parameter passing.

        Flow is followed from the Varnode and from ancestors it was copied
        from to see if it hits anything other than the given CALL or RETURN.

        C++ ref: ``Funcdata::ancestorOpUse``
        """
        def _alog(message: str) -> None:
            _paramuse_debug_log(op, trial, message)

        _alog(
            "ancestorOpUse:enter "
            f"maxlevel={maxlevel} invn={invn.getAddr().getOffset():#x}:{invn.getSize()} "
            f"written={int(invn.isWritten())} input={int(invn.isInput())} "
            f"offset={offset} mainFlags={mainFlags:#x} "
            f"def={invn.getDef().code().name + '@' + hex(invn.getDef().getAddr().getOffset()) if invn.isWritten() else 'None'}"
        )
        if maxlevel == 0:
            _paramuse_debug_log(op, trial, f"ancestorOpUse:maxlevel0 invn={invn.getAddr().getOffset():#x}:{invn.getSize()}")
            return False
        if not invn.isWritten():
            _paramuse_debug_log(
                op,
                trial,
                "ancestorOpUse:base "
                f"invn={invn.getAddr().getOffset():#x}:{invn.getSize()} "
                f"input={int(invn.isInput())} "
                f"typelock={int(invn.isTypeLock())} "
                f"mainFlags={mainFlags:#x}",
            )
            if not invn.isInput():
                _alog("ancestorOpUse:return base-not-input=0")
                return False
            if not invn.isTypeLock():
                _alog("ancestorOpUse:return base-not-typelock=0")
                return False
            res = self.onlyOpUse(invn, op, trial, mainFlags)
            _alog(f"ancestorOpUse:return base-onlyOpUse={int(res)}")
            return res

        defop = invn.getDef()
        opc = defop.code()
        if opc == OpCode.CPUI_INDIRECT:
            if defop.isIndirectCreation():
                _alog("ancestorOpUse:return indirect-creation=0")
                return False
            from ghidra.analysis.ancestor import TraverseNode
            res = self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset, mainFlags | TraverseNode.indirect)
            _alog(f"ancestorOpUse:return indirect-recurse={int(res)}")
            return res
        elif opc == OpCode.CPUI_MULTIEQUAL:
            if defop.isMark():
                _alog("ancestorOpUse:return multiequal-marked=0")
                return False
            defop.setMark()
            for j in range(defop.numInput()):
                if self.ancestorOpUse(maxlevel - 1, defop.getIn(j), op, trial, offset, mainFlags):
                    defop.clearMark()
                    _alog(f"ancestorOpUse:return multiequal-input{j}=1")
                    return True
            defop.clearMark()
            _alog("ancestorOpUse:return multiequal=0")
            return False
        elif opc == OpCode.CPUI_COPY:
            inSpace = invn.getSpace().getType()
            isIncidental = defop.isIncidentalCopy() or defop.getIn(0).isIncidentalCopy()
            if inSpace == IPTR_INTERNAL or isIncidental:
                res = self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset, mainFlags)
                _alog(f"ancestorOpUse:return copy-recurse={int(res)}")
                return res
        elif opc == OpCode.CPUI_PIECE:
            if offset == 0:
                res = self.ancestorOpUse(maxlevel - 1, defop.getIn(1), op, trial, 0, mainFlags)
                _alog(f"ancestorOpUse:return piece-lo={int(res)}")
                return res
            if offset == defop.getIn(1).getSize():
                res = self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, 0, mainFlags)
                _alog(f"ancestorOpUse:return piece-hi={int(res)}")
                return res
            _alog("ancestorOpUse:return piece-miss=0")
            return False
        elif opc == OpCode.CPUI_SUBPIECE:
            newOff = defop.getIn(1).getOffset()
            if newOff == 0:
                srcvn = defop.getIn(0)
                if srcvn.isWritten():
                    remop = srcvn.getDef()
                    if remop.code() in (OpCode.CPUI_INT_REM, OpCode.CPUI_INT_SREM):
                        trial.setRemFormed()
            inSpace = invn.getSpace().getType()
            isIncidental = defop.isIncidentalCopy() or defop.getIn(0).isIncidentalCopy()
            overlapOffset = invn.overlap(defop.getIn(0))
            if inSpace == IPTR_INTERNAL or isIncidental or overlapOffset == newOff:
                res = self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset + newOff, mainFlags)
                _alog(f"ancestorOpUse:return subpiece-recurse={int(res)}")
                return res
        elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            _alog("ancestorOpUse:return call-def=0")
            return False
        res = self.onlyOpUse(invn, op, trial, mainFlags)
        _alog(f"ancestorOpUse:return fallback-onlyOpUse={int(res)}")
        return res

    def checkCallDoubleUse(self, opmatch, op, vn, fl, trial) -> bool:
        """Check if a Varnode is legitimately used in two different call sites.

        If vn flows into a CALL/CALLIND op that is different from opmatch,
        determine if this constitutes a legitimate double-use (same function,
        same parameter slot) or if it should be considered a real alternate use.

        C++ ref: ``Funcdata::checkCallDoubleUse``
        """
        from ghidra.analysis.ancestor import TraverseNode

        j = op.getSlot(vn)
        if j <= 0:
            return False  # Flow traces to indirect call variable, not a param
        fc = self.getCallSpecs(op)
        matchfc = self.getCallSpecs(opmatch)
        if op.code() == opmatch.code():
            isdirect = (opmatch.code() == OpCode.CPUI_CALL)
            if ((isdirect and (matchfc.getEntryAddress() == fc.getEntryAddress()))
                    or ((not isdirect) and (op.getIn(0) == opmatch.getIn(0)))):
                curtrial = fc.getActiveInput().getTrialForInputVarnode(j)
                if curtrial.getAddress() == trial.getAddress():
                    if op.getParent() == opmatch.getParent():
                        if opmatch.getSeqNum().getOrder() < op.getSeqNum().getOrder():
                            return True
                    else:
                        return True

        if fc.isInputActive():
            curtrial = fc.getActiveInput().getTrialForInputVarnode(j)
            if curtrial.isChecked():
                if curtrial.isActive():
                    return False
            elif TraverseNode.isAlternatePathValid(vn, fl):
                return False
            return True
        return False

    def attemptDynamicMapping(self, entry, dhash) -> bool:
        """Map properties of a dynamic symbol to a Varnode.

        Given a dynamic mapping, try to find the mapped Varnode, then adjust
        type and flags to reflect this mapping.

        C++ ref: ``Funcdata::attemptDynamicMapping``
        """
        from ghidra.core.error import LowlevelError
        from ghidra.database.database import Symbol

        sym = entry.getSymbol()
        if sym.getScope() != self._localmap:
            raise LowlevelError("Cannot currently have a dynamic symbol outside the local scope")
        dhash.clear()
        category = sym.getCategory()
        if category == Symbol.union_facet:
            return self.applyUnionFacet(entry, dhash)
        vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
        if vn is None:
            return False
        if vn.getSymbolEntry() is not None:
            return False
        if category == Symbol.equate:
            vn.setSymbolEntry(entry)
            return True
        elif entry.getSize() == vn.getSize():
            if vn.setSymbolProperties(entry):
                return True
        return False

    def attemptDynamicMappingLate(self, entry, dhash) -> bool:
        """Map the name of a dynamic symbol to a Varnode (late pass).

        Attaches the Symbol name but may not enforce the data-type. If the
        symbol did not lock its type, the Varnode's propagated type is used.

        C++ ref: ``Funcdata::attemptDynamicMappingLate``
        """
        from ghidra.database.database import Symbol

        dhash.clear()
        sym = entry.getSymbol()
        if sym.getCategory() == Symbol.union_facet:
            return self.applyUnionFacet(entry, dhash)
        vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
        if vn is None:
            return False
        if vn.getSymbolEntry() is not None:
            return False
        if sym.getCategory() == Symbol.equate:
            vn.setSymbolEntry(entry)
            return True
        if vn.getSize() != entry.getSize():
            msg = "Unable to use symbol "
            if not sym.isNameUndefined():
                msg += sym.getName() + " "
            msg += ": Size does not match variable it labels"
            self.warningHeader(msg)
            return False
        if vn.isImplied():
            newvn = None
            if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_CAST:
                newvn = vn.getDef().getIn(0)
            else:
                castop = vn.loneDescend()
                if castop is not None and castop.code() == OpCode.CPUI_CAST:
                    newvn = castop.getOut()
            if newvn is not None and newvn.isExplicit():
                vn = newvn
        vn.setSymbolEntry(entry)
        if not sym.isTypeLocked():
            self._localmap.retypeSymbol(sym, vn.getType())
        elif sym.getType() != vn.getType():
            self.warningHeader("Unable to use type for symbol " + sym.getName())
            self._localmap.retypeSymbol(sym, vn.getType())
        return True

    # --- Iterator / search methods ---

    def endLoc(self, *args):
        """End of Varnodes sorted by storage (various overloads)."""
        if not args:
            return self._vbank.endLoc()
        if len(args) == 1:
            arg = args[0]
            if isinstance(arg, Address):
                return self._vbank.endLocAddr(arg)
            return self._vbank.endLocSpace(arg)
        if len(args) == 2:
            return self._vbank.endLocSize(args[0], args[1])
        if len(args) == 3:
            if isinstance(args[2], Address):
                return self._vbank.endLocDef(args[0], args[1], args[2])
            return self._vbank.endLocFlags(args[0], args[1], args[2])
        if len(args) == 4:
            if not isinstance(args[2], Address):
                raise TypeError("Unsupported endLoc overload")
            uniq = None if args[3] == -1 else args[3]
            return self._vbank.endLocDef(args[0], args[1], args[2], uniq)
        raise TypeError("Unsupported endLoc overload")

    def endDef(self, *args):
        """End of Varnodes sorted by definition address."""
        if not args:
            return self._vbank.endDef()
        if len(args) == 1:
            return self._vbank.endDefFlags(args[0])
        if len(args) == 2:
            return self._vbank.endDefFlagsAddr(args[0], args[1])
        raise TypeError("Unsupported endDef overload")

    def endOp(self, *args):
        """End of PcodeOp objects (by opcode or address)."""
        if args:
            return self._obank.end(*args)
        return self._obank.endAll()

    def endOpAlive(self):
        return self._obank.endAlive()

    def endOpDead(self):
        return self._obank.endDead()

    def endOpAll(self):
        return self._obank.endAll()

    def overlapLoc(self, iterobj, bounds: list) -> int:
        """Given start, return maximal range of overlapping Varnodes."""
        return self._vbank.overlapLoc(iterobj, bounds)

    def iterLocVarnodes(self, spaceid):
        """Iterate varnodes whose address space matches *spaceid*.

        C++ ref: ``VarnodeLocSet`` iteration filtered by space.
        """
        spc_bucket = self._vbank._space_varnodes.get(id(spaceid), ())
        for vn in spc_bucket:
            yield vn

    def iterDefVarnodes(self, flags: int):
        """Iterate varnodes whose flags include all bits in *flags*.

        Typically used with ``Varnode.input`` (0x08) to iterate input varnodes.
        C++ ref: ``VarnodeDefSet`` iteration filtered by flags.
        """
        for vn in self._vbank.beginDef():
            if (vn.getFlags() & flags) == flags:
                yield vn

    def beginLaneAccess(self):
        """Beginning iterator over laned accesses."""
        return iter(sorted(self._lanedMap.items(), key=lambda item: item[0]))

    def endLaneAccess(self):
        """Ending iterator over laned accesses."""
        return iter([])

    def clearLanedAccessMap(self) -> None:
        """Clear records from the laned access list."""
        self._lanedMap.clear()

    # --- Print / debug helpers ---

    def printBlockTree(self, s=None):
        """Print a description of control-flow structuring."""
        import io

        owns_stream = s is None
        out = io.StringIO() if owns_stream else s
        if self._sblocks.getSize() != 0:
            self._sblocks.printTree(out, 0)
        if owns_stream:
            return out.getvalue()
        return None

    def printVarnodeTree(self, s=None):
        """Print a description of all Varnodes."""
        import io

        owns_stream = s is None
        out = io.StringIO() if owns_stream else s
        for vn in self._vbank.beginDef():
            if hasattr(vn, "printInfo"):
                vn.printInfo(out)
            else:
                out.write(f"{vn}\n")
        if owns_stream:
            return out.getvalue()
        return None

    def printLocalRange(self, s=None):
        """Print description of memory ranges associated with local scopes.

        C++ ref: ``Funcdata::printLocalRange``
        """
        import io
        owns_stream = s is None
        out = io.StringIO() if owns_stream else s
        if self._localmap is not None:
            if hasattr(self._localmap, 'printBounds'):
                self._localmap.printBounds(out)
            if hasattr(self._localmap, 'childrenBegin'):
                for child in self._localmap.childrenBegin():
                    if hasattr(child, 'printBounds'):
                        child.printBounds(out)
        if owns_stream:
            return out.getvalue()
        return None

    # --- Misc helpers ---

    def constructConstSpacebase(self, spc):
        """Construct a constant representing the base of the given global address space.

        The constant will have the TypeSpacebase data-type set.

        C++ ref: ``Funcdata::constructConstSpacebase``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        addrSize = spc.getAddrSize()
        ct = self._glb.types.getTypeSpacebase(spc, Address())
        ptr = self._glb.types.getTypePointer(addrSize, ct, spc.getWordSize())
        spacePtr = self.newConstant(addrSize, 0)
        spacePtr.updateType(ptr, True, True)
        spacePtr.setFlags(VnCls.spacebase)
        return spacePtr

    def spacebaseConstant(self, op, slot, entry, rampoint, origval, origsize) -> None:
        """Convert a constant pointer into a ram CPUI_PTRSUB.

        A constant known to be a pointer into an address space like ram is
        converted into a Varnode defined by CPUI_PTRSUB.  The PTRSUB takes
        the constant 0 (marked spacebase) as its first input.  An additional
        INT_ADD, INT_ZEXT, or SUBPIECE may be inserted to handle offsets and
        size mismatches.

        C++ ref: ``Funcdata::spacebaseConstant``
        """
        from ghidra.core.space import AddrSpace
        from ghidra.types.datatype import TYPE_UNKNOWN

        sz = rampoint.getAddrSize()
        spaceid = rampoint.getSpace()
        sb_type = self._glb.types.getTypeSpacebase(spaceid, Address())
        sb_type = self._glb.types.getTypePointer(sz, sb_type, spaceid.getWordSize())

        entry_off = entry.getAddr().getOffset()
        extra = rampoint.getOffset() - entry_off
        extra = AddrSpace.byteToAddress(extra, rampoint.getSpace().getWordSize())

        isCopy = (op.code() == OpCode.CPUI_COPY)
        addOp = None
        extraOp = None
        zextOp = None
        subOp = None

        if isCopy:
            if sz < origsize:
                zextOp = op
            else:
                op.insertInput(1)
                if origsize < sz:
                    subOp = op
                elif extra != 0:
                    extraOp = op
                else:
                    addOp = op

        # Create spacebase constant varnode
        spacebase_vn = self.newConstant(sz, 0)
        spacebase_vn.updateType(sb_type, True, True)
        spacebase_vn.setFlags(Varnode.spacebase)

        if addOp is None:
            addOp = self.newOp(2, op.getAddr())
            self.opSetOpcode(addOp, OpCode.CPUI_PTRSUB)
            self.newUniqueOut(sz, addOp)
            self.opInsertBefore(addOp, op)
        else:
            self.opSetOpcode(addOp, OpCode.CPUI_PTRSUB)

        outvn = addOp.getOut()

        # newconstoff preserves origval in address units
        newconstoff = origval - extra
        newconst = self.newConstant(sz, newconstoff)
        if hasattr(newconst, 'setPtrCheck'):
            newconst.setPtrCheck()
        if spaceid.isTruncated():
            if hasattr(addOp, 'setPtrFlow'):
                addOp.setPtrFlow()
        self.opSetInput(addOp, spacebase_vn, 0)
        self.opSetInput(addOp, newconst, 1)

        # Assign pointer type to output
        sym = entry.getSymbol()
        entrytype = sym.getType()
        ptrentrytype = self._glb.types.getTypePointerStripArray(sz, entrytype, spaceid.getWordSize())
        typelock = sym.isTypeLocked()
        if typelock and entrytype.getMetatype() == TYPE_UNKNOWN:
            typelock = False
        outvn.updateType(ptrentrytype, typelock, False)

        if extra != 0:
            if extraOp is None:
                extraOp = self.newOp(2, op.getAddr())
                self.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD)
                self.newUniqueOut(sz, extraOp)
                self.opInsertBefore(extraOp, op)
            else:
                self.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD)
            extconst = self.newConstant(sz, extra)
            if hasattr(extconst, 'setPtrCheck'):
                extconst.setPtrCheck()
            self.opSetInput(extraOp, outvn, 0)
            self.opSetInput(extraOp, extconst, 1)
            outvn = extraOp.getOut()

        if sz < origsize:
            if zextOp is None:
                zextOp = self.newOp(1, op.getAddr())
                self.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT)
                self.newUniqueOut(origsize, zextOp)
                self.opInsertBefore(zextOp, op)
            else:
                self.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT)
            self.opSetInput(zextOp, outvn, 0)
            outvn = zextOp.getOut()
        elif origsize < sz:
            if subOp is None:
                subOp = self.newOp(2, op.getAddr())
                self.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
                self.newUniqueOut(origsize, subOp)
                self.opInsertBefore(subOp, op)
            else:
                self.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subOp, outvn, 0)
            self.opSetInput(subOp, self.newConstant(4, 0), 1)
            outvn = subOp.getOut()

        if not isCopy:
            self.opSetInput(op, outvn, slot)

    def switchOverJumpTables(self, flow) -> None:
        """Convert jump-table addresses to basic block indices."""
        for jt in self._jumpvec:
            jt.switchOver(flow)

    def issueDatatypeWarnings(self) -> None:
        """Add warning headers for any data-types that have been modified.

        C++ ref: ``Funcdata::issueDatatypeWarnings``
        """
        if self._glb is None:
            return
        if hasattr(self._glb, 'types') and self._glb.types is not None:
            for warning in self._glb.types.beginWarnings():
                self.warningHeader(warning.getWarning())

    def enableJTCallback(self, cb) -> None:
        """Enable a jump-table callback."""
        self._jtcallback = cb

    def disableJTCallback(self) -> None:
        """Disable the jump-table callback."""
        self._jtcallback = None

    def stageJumpTable(self, partial, jt, op, flow):
        """Stage jump-table analysis on a partial clone of the function.

        If the partial Funcdata has not yet been analyzed for jump-table
        recovery, a truncated flow is generated and the 'jumptable' action
        group is run to simplify the partial function. Then the BRANCHIND
        in the partial is located and the JumpTable is asked to recover
        addresses from the simplified IR.

        C++ ref: ``Funcdata::stageJumpTable``

        Args:
            partial: A Funcdata clone used for jump-table analysis.
            jt: The JumpTable object to fill in.
            op: The BRANCHIND PcodeOp in the original function.
            flow: The FlowInfo for the original function (or None).

        Returns:
            A recovery mode string: 'success', 'fail_normal', 'fail_return',
            'fail_thunk', or None on error.
        """
        from ghidra.analysis.jumptable import JumptableThunkError
        from ghidra.core.error import LowlevelError

        if not partial.isJumptableRecoveryOn():
            partial._flags |= Funcdata.jumptablerecovery_on
            partial.truncatedFlow(self, flow)

            oldactname = self._glb.allacts.getCurrentName()
            try:
                self._glb.allacts.setCurrent("jumptable")
                jtcallback = self._jtcallback
                if jtcallback is not None:
                    jtcallback(self, partial)
                else:
                    cur = self._glb.allacts.getCurrent()
                    cur.reset(partial)
                    cur.perform(partial)
                self._glb.allacts.setCurrent(oldactname)
            except LowlevelError as err:
                self._glb.allacts.setCurrent(oldactname)
                self.warning(err.explain, op.getAddr())
                return 'fail_normal'

        partop = partial.findOp(op.getSeqNum())

        if partop is None or partop.code() != OpCode.CPUI_BRANCHIND or partop.getAddr() != op.getAddr():
            raise LowlevelError("Error recovering jumptable: Bad partial clone")
        if partop.isDead():
            return 'success'

        # Test if the branch target is copied from the return address
        if self.testForReturnAddress(partop.getIn(0)):
            return 'fail_return'

        try:
            jt.setLoadCollect(flow.doesJumpRecord())
            jt.setIndirectOp(partop)
            if jt.isPartial():
                jt.recoverMultistage(partial)
            else:
                jt.recoverAddresses(partial)
        except JumptableThunkError:
            return 'fail_thunk'
        except LowlevelError as err:
            self.warning(err.explain, op.getAddr())
            return 'fail_normal'
        return 'success'

    # --- Block routines ---

    def getBasicBlockCount(self) -> int:
        return self._bblocks.getSize()

    def getBlock(self, i: int):
        return self._bblocks.getBlock(i)

    def opInsertBegin(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the beginning of a basic block.

        C++ ref: ``Funcdata::opInsertBegin``
        """
        from ghidra.core.opcodes import OpCode

        idx = 0
        ops = bl.getOpList()
        if op.code() != OpCode.CPUI_MULTIEQUAL:
            while idx < len(ops):
                if ops[idx].code() != OpCode.CPUI_MULTIEQUAL:
                    break
                idx += 1
        self.opInsert(op, bl, idx)

    def opInsertEnd(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the end of a basic block.

        C++ ref: ``Funcdata::opInsertEnd``
        """
        ops = bl.getOpList()
        idx = len(ops)
        if idx != 0:
            idx -= 1
            if not ops[idx].isFlowBreak():
                idx += 1
        self.opInsert(op, bl, idx)

    def opInsertAfter(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert op after a specific PcodeOp in its basic block.

        C++ ref: ``Funcdata::opInsertAfter``
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.core.space import IPTR_IOP
        from ghidra.ir.op import PcodeOp

        if prev.isMarker():
            if prev.code() == OpCode.CPUI_INDIRECT:
                invn = prev.getIn(1)
                if invn.getSpace().getType() == IPTR_IOP:
                    targ_op = PcodeOp.getOpFromConst(invn.getAddr())
                    if not targ_op.isDead():
                        prev = targ_op

        bl = prev.getParent()
        ops = bl.getOpList()
        idx = ops.index(prev)
        idx += 1
        if op.code() != OpCode.CPUI_MULTIEQUAL:
            while idx < len(ops):
                nextop = ops[idx]
                idx += 1
                if nextop.code() != OpCode.CPUI_MULTIEQUAL:
                    idx -= 1
                    break
        self.opInsert(op, prev.getParent(), idx)
        _debug_insert_event("opInsertAfter", op, prev, bl)

    def opInsertBefore(self, op: PcodeOp, follow: PcodeOp) -> None:
        """Insert op before a specific PcodeOp in its basic block.

        If the op being inserted is NOT an INDIRECT, walk backwards past
        any preceding INDIRECT ops so that non-INDIRECT ops are placed
        before the INDIRECT cluster.  This matches C++ semantics where
        INDIRECTs must remain immediately before their associated CALL.

        C++ ref: ``Funcdata::opInsertBefore``
        """
        from ghidra.core.opcodes import OpCode
        bl = follow.getParent()
        ops = bl.getOpList()
        idx = ops.index(follow)
        if op.code() != OpCode.CPUI_INDIRECT:
            while idx > 0 and ops[idx - 1].code() == OpCode.CPUI_INDIRECT:
                idx -= 1
        self.opInsert(op, bl, idx)
        _debug_insert_event("opInsertBefore", op, follow, bl)

    # --- Warning / comment ---

    def warning(self, txt: str, ad: Address) -> None:
        """Add a warning comment in the function body.

        C++ ref: ``Funcdata::warning``
        """
        from ghidra.database.comment import Comment

        if (self._flags & Funcdata.jumptablerecovery_on) != 0:
            msg = "WARNING (jumptable): "
        else:
            msg = "WARNING: "
        msg += txt
        if self._glb is not None and hasattr(self._glb, 'commentdb') and self._glb.commentdb is not None:
            self._glb.commentdb.addCommentNoDuplicate(Comment.CommentType.warning, self._baseaddr, ad, msg)
        elif self._glb is not None and hasattr(self._glb, 'printMessage'):
            self._glb.printMessage(msg)

    def warningHeader(self, txt: str) -> None:
        """Add a warning comment in the function header.

        C++ ref: ``Funcdata::warningHeader``
        """
        from ghidra.database.comment import Comment

        if (self._flags & Funcdata.jumptablerecovery_on) != 0:
            msg = "WARNING (jumptable): "
        else:
            msg = "WARNING: "
        msg += txt
        if self._glb is not None and hasattr(self._glb, 'commentdb') and self._glb.commentdb is not None:
            self._glb.commentdb.addCommentNoDuplicate(
                Comment.CommentType.warningheader,
                self._baseaddr,
                self._baseaddr,
                msg,
            )
        elif self._glb is not None and hasattr(self._glb, 'printMessage'):
            self._glb.printMessage(msg)

    # --- Flow and inline ---

    def followFlow(self, baddr, eaddr) -> None:
        """Generate raw p-code and basic blocks for the function body.

        C++ ref: ``Funcdata::followFlow``
        """
        from ghidra.analysis.flow import FlowInfo
        from ghidra.core.error import LowlevelError

        if not self._obank.empty():
            if (self._flags & Funcdata.blocks_generated) == 0:
                raise LowlevelError("Function loaded for inlining")
            return

        flow = FlowInfo(self, self._obank, self._bblocks, self._qlst)
        flow.setRange(baddr, eaddr)
        flow.setFlags(self._glb.flowoptions if self._glb else 0)
        flow.setMaximumInstructions(self._glb.max_instructions if self._glb else 100000)
        flow.generateOps()
        self._size = flow.getSize()
        flow.generateBlocks()
        self._flags |= Funcdata.blocks_generated
        self.switchOverJumpTables(flow)
        if flow.hasUnimplemented():
            self._flags |= Funcdata.unimplemented_present
        if flow.hasBadData():
            self._flags |= Funcdata.baddata_present

    def truncatedFlow(self, fd, flow) -> None:
        """Generate a truncated set of p-code from an existing flow.

        C++ ref: ``Funcdata::truncatedFlow``
        """
        from ghidra.analysis.flow import FlowInfo
        from ghidra.analysis.jumptable import JumpTable
        from ghidra.core.error import LowlevelError
        from ghidra.core.space import IPTR_FSPEC

        if not self._obank.empty():
            raise LowlevelError("Trying to do truncated flow on pre-existing pcode")

        for op in list(fd._obank.getDeadList()):
            self.cloneOp(op, op.getSeqNum())
        self._obank.setUniqId(fd._obank.getUniqId())

        for oldspec in list(fd._qlst):
            newop = self.findOp(oldspec.getOp().getSeqNum())
            newspec = oldspec.clone(newop)
            invn0 = newop.getIn(0)
            if invn0 is not None and invn0.getSpace().getType() == IPTR_FSPEC:
                newvn0 = self.newVarnodeCallSpecs(newspec)
                self.opSetInput(newop, newvn0, 0)
                self.deleteVarnode(invn0)
            self.addCallSpecs(newspec)

        for oldjt in list(fd._jumpvec):
            indop = oldjt.getIndirectOp()
            if indop is None:
                continue
            newop = self.findOp(indop.getSeqNum())
            if newop is None:
                raise LowlevelError("Could not trace jumptable across partial clone")

            jtclone = JumpTable(oldjt)
            jtclone.setIndirectOp(newop)
            self._jumpvec.append(jtclone)

        partialflow = FlowInfo(self, self._obank, self._bblocks, self._qlst, flow)
        if partialflow.hasInject():
            partialflow.injectPcode()
        partialflow.clearFlags(~FlowInfo.possible_unreachable)
        partialflow.generateBlocks()
        self._flags |= Funcdata.blocks_generated

    def inlineFlow(self, inlinefd, flow, callop) -> int:
        """In-line the p-code of another function into \b this function.

        Raw p-code is generated for the in-lined function, then control-flow
        information is cloned into the current FlowInfo object. This method
        supports two in-lining models:
          - The EZ model: the in-lined function is a single basic-block
            with no calls or branches. P-code is cloned and simply replaces
            the CALL op.
          - The hard model: the in-lined function has real control-flow.
            The CALL op is converted to a BRANCH to the in-lined body, and
            the in-lined RETURN ops become branches back to the call site
            fall-through.

        C++ ref: ``Funcdata::inlineFlow``

        Args:
            inlinefd: Funcdata of the function being in-lined.
            flow: FlowInfo object for the current function.
            callop: The CALL PcodeOp being replaced.

        Returns:
            0 for EZ model success, 1 for hard model success, -1 on failure.
        """
        from ghidra.analysis.flow import FlowInfo

        if inlinefd.getArch() is not None and hasattr(inlinefd.getArch(), 'clearAnalysis'):
            inlinefd.getArch().clearAnalysis(inlinefd)

        inlineflow = FlowInfo(inlinefd, inlinefd._obank, inlinefd._bblocks, inlinefd._qlst)
        inlinefd._obank.setUniqId(self._obank.getUniqId())

        # Generate the pcode ops to be inlined
        baddr = Address(self._baseaddr.getSpace(), 0)
        eaddr = Address(self._baseaddr.getSpace(), 0xFFFFFFFFFFFFFFFF)
        inlineflow.setRange(baddr, eaddr)
        inlineflow.setFlags(FlowInfo.error_outofbounds | FlowInfo.error_unimplemented |
                            FlowInfo.error_reinterpreted | FlowInfo.flow_forinline)
        inlineflow.forwardRecursion(flow)
        inlineflow.generateOps()

        if inlineflow.checkEZModel():
            res = 0
            # With an EZ clone there are no jumptables to clone
            deadlist = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []
            lastidx = len(deadlist) - 1  # There is at least one op

            flow.inlineEZClone(inlineflow, callop.getAddr())

            newdeadlist = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []
            # Find ops that were added after the EZ clone
            newops = newdeadlist[lastidx + 1:] if lastidx + 1 < len(newdeadlist) else []

            if newops:
                firstop = newops[0]
                lastop = newops[-1]
                self._obank.moveSequenceDead(firstop, lastop, callop)
                if callop.isBlockStart():
                    firstop.setFlag(PcodeOp.startbasic)
                    flow.updateTarget(callop, firstop)
                else:
                    firstop.clearFlag(PcodeOp.startbasic)
            self.opDestroyRaw(callop)
        else:
            retaddr_ref = [Address()]
            if not flow.testHardInlineRestrictions(inlinefd, callop, retaddr_ref):
                return -1
            retaddr = retaddr_ref[0]
            res = 1
            # Clone any jumptables from inline piece
            for jt_orig in inlinefd._jumpvec:
                from ghidra.analysis.jumptable import JumpTable
                jtclone = JumpTable(jt_orig)
                self._jumpvec.append(jtclone)

            flow.inlineClone(inlineflow, retaddr)

            # Convert CALL op to a jump
            while callop.numInput() > 1:
                self.opRemoveInput(callop, callop.numInput() - 1)

            self.opSetOpcode(callop, OpCode.CPUI_BRANCH)
            inlineaddr = self.newCodeRef(inlinefd.getAddress())
            self.opSetInput(callop, inlineaddr, 0)

        self._obank.setUniqId(inlinefd._obank.getUniqId())

        return res

    def overrideFlow(self, addr, flowtype: int) -> None:
        """Override the control-flow p-code for a particular instruction.

        P-code in this function is modified to change the control-flow of
        the instruction at the given address, based on the Override type.

        C++ ref: ``Funcdata::overrideFlow``
        """
        # Override type constants (from override.hh)
        OVERRIDE_NONE = 0
        OVERRIDE_BRANCH = 1
        OVERRIDE_CALL = 2
        OVERRIDE_CALL_RETURN = 3
        OVERRIDE_RETURN = 4

        # Match the native beginOp(addr)/endOp(addr) walk over the ordered op-tree.
        ops_at_addr = []
        if hasattr(self._obank, 'beginByAddr'):
            ops_at_addr = list(self._obank.beginByAddr(addr))

        op = None
        if flowtype == OVERRIDE_BRANCH:
            op = self.findPrimaryBranch(ops_at_addr, False, True, True)
        elif flowtype == OVERRIDE_CALL:
            op = self.findPrimaryBranch(ops_at_addr, True, False, True)
        elif flowtype == OVERRIDE_CALL_RETURN:
            op = self.findPrimaryBranch(ops_at_addr, True, True, True)
        elif flowtype == OVERRIDE_RETURN:
            op = self.findPrimaryBranch(ops_at_addr, True, True, False)

        if op is None or not op.isDead():
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Could not apply flowoverride")

        opc = op.code()
        if flowtype == OVERRIDE_BRANCH:
            if opc == OpCode.CPUI_CALL:
                self.opSetOpcode(op, OpCode.CPUI_BRANCH)
            elif opc == OpCode.CPUI_CALLIND:
                self.opSetOpcode(op, OpCode.CPUI_BRANCHIND)
            elif opc == OpCode.CPUI_RETURN:
                self.opSetOpcode(op, OpCode.CPUI_BRANCHIND)
        elif flowtype in (OVERRIDE_CALL, OVERRIDE_CALL_RETURN):
            if opc == OpCode.CPUI_BRANCH:
                self.opSetOpcode(op, OpCode.CPUI_CALL)
            elif opc == OpCode.CPUI_BRANCHIND:
                self.opSetOpcode(op, OpCode.CPUI_CALLIND)
            elif opc == OpCode.CPUI_CBRANCH:
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Do not currently support CBRANCH overrides")
            elif opc == OpCode.CPUI_RETURN:
                self.opSetOpcode(op, OpCode.CPUI_CALLIND)
            if flowtype == OVERRIDE_CALL_RETURN:
                # Insert a new return op after call
                newReturn = self.newOp(1, addr)
                self.opSetOpcode(newReturn, OpCode.CPUI_RETURN)
                self.opSetInput(newReturn, self.newConstant(1, 0), 0)
                self.opDeadInsertAfter(newReturn, op)
        elif flowtype == OVERRIDE_RETURN:
            if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH, OpCode.CPUI_CALL):
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Do not currently support complex overrides")
            elif opc == OpCode.CPUI_BRANCHIND:
                self.opSetOpcode(op, OpCode.CPUI_RETURN)
            elif opc == OpCode.CPUI_CALLIND:
                self.opSetOpcode(op, OpCode.CPUI_RETURN)

    def doLiveInject(self, payload, addr, bl, pos) -> None:
        """Inject p-code from a payload into a live basic block.

        Raw PcodeOps are generated from the payload into the dead list,
        then each injected op is moved into the basic block at the given
        insertion point.  Branching injections are illegal and raise an error.

        C++ ref: ``Funcdata::doLiveInject``
        """
        from ghidra.sleigh.pcodeemit import PcodeEmitFd

        injectlib = self._glb.pcodeinjectlib
        emitter = PcodeEmitFd()
        emitter.setFuncdata(self)

        context = injectlib.getCachedContext()
        context.clear()
        context.baseaddr = addr
        context.nextaddr = addr

        dead_before = list(self._obank.getDeadList())
        deadempty = len(dead_before) == 0
        old_last = None if deadempty else dead_before[-1]

        payload.inject(context, emitter)

        dead_after = list(self._obank.getDeadList())
        if deadempty:
            injected = dead_after
        else:
            start_index = -1
            for idx, op in enumerate(dead_after):
                if op is old_last:
                    start_index = idx
                    break
            injected = dead_after[start_index + 1:] if start_index >= 0 else []

        # Insert each injected op into the basic block
        for op in injected:
            if hasattr(op, 'isCallOrBranch') and op.isCallOrBranch():
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Illegal branching injection")
            self.opInsert(op, bl, pos)

    # --- Clone / Indirect ---

    def cloneOp(self, op, seq):
        """Clone a PcodeOp, copying control-flow properties.

        The data-type is not cloned.

        C++ ref: ``Funcdata::cloneOp``
        """
        newop = self.newOp(op.numInput(), seq)
        self.opSetOpcode(newop, op.code())
        fl = op._flags & (PcodeOp.startmark | PcodeOp.startbasic)
        newop.setFlag(fl)
        if op.getOut() is not None:
            self.opSetOutput(newop, self.cloneVarnode(op.getOut()))
        for i in range(op.numInput()):
            self.opSetInput(newop, self.cloneVarnode(op.getIn(i)), i)
        return newop

    def newIndirectOp(self, indeffect, addr, sz: int, extraFlags: int = 0):
        """Create a new CPUI_INDIRECT around a PcodeOp with an indirect effect.

        An output Varnode is automatically created.

        C++ ref: ``Funcdata::newIndirectOp``
        """
        from ghidra.core.opcodes import OpCode
        newin = self.newVarnode(sz, addr)
        newop = self.newOp(2, indeffect.getAddr())
        newop.setFlag(extraFlags)
        self.newVarnodeOut(sz, addr, newop)
        self.opSetOpcode(newop, OpCode.CPUI_INDIRECT)
        self.opSetInput(newop, newin, 0)
        self.opSetInput(newop, self.newVarnodeIop(indeffect), 1)
        self.opInsertBefore(newop, indeffect)
        return newop

    def newIndirectCreation(self, indeffect, addr, sz: int, possibleout: bool):
        """Build a CPUI_INDIRECT op that indirectly creates a Varnode.

        An indirectly created Varnode has no data-flow before the INDIRECT.

        C++ ref: ``Funcdata::newIndirectCreation``
        """
        from ghidra.core.opcodes import OpCode
        newin = self.newConstant(sz, 0)
        newop = self.newOp(2, indeffect.getAddr())
        newop.setFlag(PcodeOp.indirect_creation)
        newout = self.newVarnodeOut(sz, addr, newop)
        if not possibleout:
            newin.setFlags(Varnode.indirect_creation)
        newout.setFlags(Varnode.indirect_creation)
        self.opSetOpcode(newop, OpCode.CPUI_INDIRECT)
        self.opSetInput(newop, newin, 0)
        self.opSetInput(newop, self.newVarnodeIop(indeffect), 1)
        self.opInsertBefore(newop, indeffect)
        return newop

    def markIndirectCreation(self, indop, possibleOutput: bool) -> None:
        """Mark an existing CPUI_INDIRECT as an indirect creation.

        C++ ref: ``Funcdata::markIndirectCreation``
        """
        from ghidra.core.error import LowlevelError

        outvn = indop.getOut()
        in0 = indop.getIn(0)
        indop.setFlag(PcodeOp.indirect_creation)
        if not in0.isConstant():
            raise LowlevelError("Indirect creation not properly formed")
        if not possibleOutput:
            in0.setFlags(Varnode.indirect_creation)
        outvn.setFlags(Varnode.indirect_creation)

    def opInsert(self, op, bl, pos) -> None:
        """Insert a PcodeOp into a specific position in a basic block."""
        self.opMarkAlive(op)
        if pos is None:
            pos = len(bl.getOpList())
        bl.insertOp(op, pos)

    def opUninsert(self, op) -> None:
        """Remove the given PcodeOp from its basic block without destroying it."""
        self._obank.markDead(op)
        op.getParent().removeOp(op)

    def opDeadInsertAfter(self, op, prev) -> None:
        """Insert op after prev in the dead list."""
        self._obank.insertAfterDead(op, prev)

    def opDestroyRecursive(self, op, scratch: list = None) -> None:
        """Remove a PcodeOp and recursively remove ops producing its inputs.

        PcodeOps are iteratively removed if the only data-flow path of
        their output is to the given op, and they are not a CALL or
        otherwise special.

        C++ ref: ``Funcdata::opDestroyRecursive``
        """
        if scratch is None:
            scratch = []
        scratch.clear()
        scratch.append(op)
        pos = 0
        while pos < len(scratch):
            curop = scratch[pos]
            pos += 1
            for i in range(curop.numInput()):
                vn = curop.getIn(i)
                if not vn.isWritten():
                    continue
                if vn.isAutoLive():
                    continue
                if vn.loneDescend() is None:
                    continue
                defOp = vn.getDef()
                if defOp.isCall():
                    continue
                if defOp.isIndirectSource():
                    continue
                scratch.append(defOp)
            self.opDestroy(curop)

    # --- Varnode search / link ---

    def findLinkedVarnode(self, entry):
        """Return the first Varnode matching the given SymbolEntry.

        For dynamic entries, uses DynamicHash. For non-dynamic entries,
        iterates Varnodes at the entry's location, checking usepoint.

        C++ ref: ``Funcdata::findLinkedVarnode``
        """
        if entry.isDynamic():
            from ghidra.analysis.dynamic import DynamicHash

            dhash = DynamicHash()
            vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
            if vn is None or vn.isAnnotation():
                return None
            return vn

        usestart = entry.getFirstUseAddress()
        if usestart.isInvalid():
            loclist = self.beginLoc(entry.getSize(), entry.getAddr())
            if not loclist:
                return None
            vn = loclist[0]
            if not vn.isAddrTied():
                return None
            return vn

        for vn in self.beginLoc(entry.getSize(), entry.getAddr(), usestart, (1 << 64) - 1):
            usepoint = vn.getUsePoint(self)
            if entry.inUse(usepoint):
                return vn
        return None

    def findLinkedVarnodes(self, entry, res: list) -> None:
        """Find Varnodes that map to the given SymbolEntry.

        For dynamic entries, uses DynamicHash. For non-dynamic entries,
        iterates Varnodes at the entry's location, checking usepoint.

        C++ ref: ``Funcdata::findLinkedVarnodes``
        """
        if entry.isDynamic():
            from ghidra.analysis.dynamic import DynamicHash

            dhash = DynamicHash()
            vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
            if vn is not None:
                res.append(vn)
            return
        for vn in self.beginLoc(entry.getSize(), entry.getAddr()):
            usepoint = vn.getUsePoint(self)
            if entry.inUse(usepoint):
                res.append(vn)

    def linkSymbol(self, vn):
        """Find or create a Symbol associated with the given Varnode.

        If the Varnode is a proto-partial, delegate to linkProtoPartial first.
        Then check for an existing Symbol on the HighVariable. If none, query
        the local scope for an overlapping entry and either handle a conflict
        or create a new local symbol.

        C++ ref: ``Funcdata::linkSymbol``
        """
        if vn.isProtoPartial():
            self.linkProtoPartial(vn)
        high = vn.getHigh()
        sym = high.getSymbol()
        if sym is not None:
            return sym
        fl_ref = [0]
        usepoint = vn.getUsePoint(self)
        entry = self._localmap.queryProperties(vn.getAddr(), 1, usepoint, fl_ref)
        if entry is not None:
            sym = self.handleSymbolConflict(entry, vn)
        else:
            # Must create a symbol entry
            if not vn.isPersist():
                if vn.isAddrTied():
                    usepoint = Address()
                entry = self._localmap.addSymbol("", high.getType(), vn.getAddr(), usepoint)
                sym = entry.getSymbol()
                vn.setSymbolEntry(entry)
            else:
                sym = None
        return sym

    def linkSymbolReference(self, vn):
        """Recover the Symbol referred to by a constant Varnode in a PTRSUB op.

        A reference to a symbol (&varname) is typically stored as a PTRSUB
        where the first input is a spacebase Varnode and the second is a
        constant encoding the symbol's address.

        C++ ref: ``Funcdata::linkSymbolReference``
        """
        from ghidra.core.error import LowlevelError
        from ghidra.types.datatype import TYPE_PTR, TYPE_SPACEBASE

        op = vn.loneDescend()
        in0 = op.getIn(0)
        ptype = in0.getHigh().getType()
        if ptype.getMetatype() != TYPE_PTR:
            return None
        sb = ptype.getPtrTo()
        if sb.getMetatype() != TYPE_SPACEBASE:
            return None
        scope = sb.getMap()
        addr = sb.getAddress(vn.getOffset(), in0.getSize(), op.getAddr())
        if addr.isInvalid():
            raise LowlevelError("Unable to generate proper address from spacebase")
        entry = scope.queryContainer(addr, 1, Address())
        if entry is None:
            return None
        off = int(addr.getOffset() - entry.getAddr().getOffset()) + entry.getOffset()
        vn.setSymbolReference(entry, off)
        return entry.getSymbol()

    def linkProtoPartial(self, vn) -> None:
        """Link a proto-partial Varnode to its whole Symbol.

        PIECE operations put the given Varnode into a larger structure.  Find
        the resulting whole Varnode, make sure it has a symbol assigned, and
        then assign the same symbol to the given Varnode piece.

        C++ ref: ``Funcdata::linkProtoPartial``
        """
        high = vn.getHigh()
        if high.getSymbol() is not None:
            return
        rootVn = PieceNode.findRoot(vn)
        if rootVn is vn:
            return
        rootHigh = rootVn.getHigh()
        if not rootHigh.isSameGroup(high):
            return
        nameRep = rootHigh.getNameRepresentative()
        sym = self.linkSymbol(nameRep)
        if sym is None:
            return
        rootHigh.establishGroupSymbolOffset()
        entry = sym.getFirstWholeMap()
        vn.setSymbolEntry(entry)

    def buildDynamicSymbol(self, vn) -> None:
        """Build a dynamic Symbol associated with the given Varnode.

        If a Symbol is already attached, no change is made. Otherwise a special
        dynamic Symbol is created that is associated with the Varnode via a hash
        of its local data-flow.

        C++ ref: ``Funcdata::buildDynamicSymbol``
        """
        from ghidra.analysis.dynamic import DynamicHash
        from ghidra.core.error import RecovError
        from ghidra.database.database import Symbol

        if vn.isTypeLock() or vn.isNameLock():
            raise RecovError("Trying to build dynamic symbol on locked varnode")
        if not self.isHighOn():
            raise RecovError("Cannot create dynamic symbols until decompile has completed")
        high = vn.getHigh()
        if high.getSymbol() is not None:
            return

        dhash = DynamicHash()
        dhash.uniqueHash(vn, self)
        if dhash.getHash() == 0:
            raise RecovError("Unable to find unique hash for varnode")

        if vn.isConstant():
            sym = self._localmap.addEquateSymbol(
                "",
                Symbol.force_hex,
                vn.getOffset(),
                dhash.getAddress(),
                dhash.getHash(),
            )
        else:
            sym = self._localmap.addDynamicSymbol(
                "",
                high.getType(),
                dhash.getAddress(),
                dhash.getHash(),
            )
        vn.setSymbolEntry(sym.getFirstWholeMap())

    def combineInputVarnodes(self, vnHi, vnLo) -> None:
        """Combine two contiguous input Varnodes into one.

        Find all PIECE ops that directly combine vnHi and vnLo, convert them
        to COPYs of the new combined input. For other uses of vnHi/vnLo,
        create SUBPIECE ops to extract the original pieces.

        C++ ref: ``Funcdata::combineInputVarnodes``
        """
        from ghidra.core.error import LowlevelError

        if not vnHi.isInput() or not vnLo.isInput():
            raise LowlevelError("Varnodes being combined are not inputs")
        addr = vnLo.getAddr()
        if addr.isBigEndian():
            addr = vnHi.getAddr()
            otheraddr = addr + vnHi.getSize()
            isContiguous = (otheraddr == vnLo.getAddr())
        else:
            otheraddr = addr + vnLo.getSize()
            isContiguous = (otheraddr == vnHi.getAddr())
        if not isContiguous:
            raise LowlevelError("Input varnodes being combined are not contiguous")

        # Find PIECE ops that directly combine hi and lo
        pieceList = []
        otherOpsHi = False
        otherOpsLo = False
        for op in list(vnHi.getDescendants()):
            if op.code() == OpCode.CPUI_PIECE and op.getIn(0) is vnHi and op.getIn(1) is vnLo:
                pieceList.append(op)
            else:
                otherOpsHi = True
        for op in list(vnLo.getDescendants()):
            if op.code() != OpCode.CPUI_PIECE or op.getIn(0) is not vnHi or op.getIn(1) is not vnLo:
                otherOpsLo = True

        # Remove the lo input from PIECE ops and unset hi input
        for pieceOp in pieceList:
            if hasattr(self, 'opRemoveInput'):
                self.opRemoveInput(pieceOp, 1)
            self.opUnsetInput(pieceOp, 0)

        # Create SUBPIECE replacements for non-PIECE uses
        subHi = None
        subLo = None
        if otherOpsHi:
            bb = self._bblocks.getBlock(0)
            subHi = self.newOp(2, bb.getStart())
            self.opSetOpcode(subHi, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subHi, self.newConstant(4, vnLo.getSize()), 1)
            newHi = self.newVarnodeOut(vnHi.getSize(), vnHi.getAddr(), subHi)
            self.opInsertBegin(subHi, bb)
            self.totalReplace(vnHi, newHi)
        if otherOpsLo:
            bb = self._bblocks.getBlock(0)
            subLo = self.newOp(2, bb.getStart())
            self.opSetOpcode(subLo, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subLo, self.newConstant(4, 0), 1)
            newLo = self.newVarnodeOut(vnLo.getSize(), vnLo.getAddr(), subLo)
            self.opInsertBegin(subLo, bb)
            self.totalReplace(vnLo, newLo)

        # Destroy old inputs and create the combined input
        outSize = vnHi.getSize() + vnLo.getSize()
        self._vbank.destroy(vnHi)
        self._vbank.destroy(vnLo)
        inVn = self.newVarnode(outSize, addr)
        inVn = self.setInputVarnode(inVn)

        # Wire up PIECE ops as COPYs of the combined input
        for pieceOp in pieceList:
            self.opSetInput(pieceOp, inVn, 0)
            self.opSetOpcode(pieceOp, OpCode.CPUI_COPY)
        if subHi is not None:
            self.opSetInput(subHi, inVn, 0)
        if subLo is not None:
            self.opSetInput(subLo, inVn, 0)

    def findSpacebaseInput(self, spc):
        """Try to locate the unique input Varnode holding the base register for the given space.

        C++ ref: ``Funcdata::findSpacebaseInput``
        """
        base = spc.getSpacebase(0)
        addr = Address(base.space, base.offset)
        return self._vbank.findInput(base.size, addr)

    def constructSpacebaseInput(self, spc):
        """If it doesn't exist, create an input Varnode of the base register for the given space.

        If an input varnode for the spacebase already exists, return it.
        Otherwise create a new one, mark it as spacebase, and assign the
        TypeSpacebase pointer type.

        C++ ref: ``Funcdata::constructSpacebaseInput``
        """
        from ghidra.core.error import LowlevelError
        from ghidra.ir.varnode import Varnode as VnCls
        spacePtr = self.findSpacebaseInput(spc)
        if spacePtr is not None:
            return spacePtr
        if spc.numSpacebase() == 0:
            raise LowlevelError("Unable to construct pointer into space: " + spc.getName())
        base = spc.getSpacebase(0)
        addr = Address(base.space, base.offset)
        ct = self._glb.types.getTypeSpacebase(spc, self.getAddress())
        ptr = self._glb.types.getTypePointer(base.size, ct, spc.getWordSize())
        spacePtr = self.newVarnode(base.size, addr, ptr)
        spacePtr = self.setInputVarnode(spacePtr)
        spacePtr.setFlags(VnCls.spacebase)
        spacePtr.updateType(ptr, True, True)
        return spacePtr

    def newSpacebasePtr(self, spc):
        """Construct a new (non-input) spacebase Varnode for a given address space.

        C++ ref: ``Funcdata::newSpacebasePtr``
        """
        if spc is None or not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            raise Exception("Unable to construct pointer into space")
        base = spc.getSpacebase(0)
        addr = base.getAddr() if hasattr(base, 'getAddr') else Address(base.space, base.offset)
        return self.newVarnode(base.size, addr)

    def hasInputIntersection(self, s: int, loc) -> bool:
        return self._vbank.hasInputIntersection(s, loc)

    def getAliveOps(self):
        """Get all alive PcodeOps as an iterable."""
        if hasattr(self._obank, 'getAliveList'):
            return self._obank.getAliveList()
        return []

    def getStoreGuards(self):
        return self._heritage.getStoreGuards()

    def getLoadGuards(self):
        return self._heritage.getLoadGuards()

    def getStoreGuard(self, op):
        return self._heritage.getStoreGuard(op)

    # --- Encode / decode ---

    @staticmethod
    def encodeVarnode(encoder, iter_vns, enditer=None) -> None:
        """Encode a set of Varnodes to stream.

        C++ ref: ``Funcdata::encodeVarnode``
        """
        for vn in iter_vns:
            vn.encode(encoder)

    def encode(self, encoder, uid: int = 0, savetree: bool = True) -> None:
        """Encode a description of this function to stream.

        C++ ref: ``Funcdata::encode``
        """
        from ghidra.core.marshal import (
            ELEM_FUNCTION, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_NOCODE,
        )
        encoder.openElement(ELEM_FUNCTION)
        if uid != 0:
            encoder.writeUnsignedInteger(ATTRIB_ID, uid)
        encoder.writeString(ATTRIB_NAME, self._name)
        encoder.writeSignedInteger(ATTRIB_SIZE, self._size)
        if self.hasNoCode():
            encoder.writeBool(ATTRIB_NOCODE, True)
        self._baseaddr.encode(encoder)

        if not self.hasNoCode():
            if self._localmap is not None:
                self._localmap.encodeRecursive(encoder, False)

        if savetree:
            self.encodeTree(encoder)
            self.encodeHigh(encoder)
        self.encodeJumpTable(encoder)
        self._funcp.encode(encoder)
        if hasattr(self, '_localoverride') and self._localoverride is not None:
            self._localoverride.encode(encoder, self._glb)
        encoder.closeElement(ELEM_FUNCTION)

    def decode(self, decoder) -> int:
        """Restore the state of this function from a stream.

        C++ ref: ``Funcdata::decode``
        """
        from ghidra.core.error import LowlevelError
        from ghidra.core.marshal import (
            ELEM_FUNCTION, ELEM_LOCALDB, ELEM_OVERRIDE, ELEM_PROTOTYPE,
            ELEM_JUMPTABLELIST, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_ID,
            ATTRIB_NOCODE, ATTRIB_LABEL,
        )
        from ghidra.database.varmap import ScopeLocal

        self._name = ""
        self._displayName = ""
        self._size = -1
        uid = 0
        stackid = self._glb.getStackSpace() if self._glb is not None and hasattr(self._glb, "getStackSpace") else None
        symboltab = getattr(self._glb, "symboltab", None)
        elemId = decoder.openElement(ELEM_FUNCTION)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME:
                self._name = decoder.readString()
            elif attribId == ATTRIB_SIZE:
                self._size = decoder.readSignedInteger()
            elif attribId == ATTRIB_ID:
                uid = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_NOCODE:
                if decoder.readBool():
                    self._flags |= Funcdata.no_code
            elif attribId == ATTRIB_LABEL:
                self._displayName = decoder.readString()
        if not self._name:
            raise LowlevelError("Missing function name")
        if not self._displayName:
            self._displayName = self._name
        if self._size == -1:
            raise LowlevelError("Missing function size")
        self._baseaddr = Address.decode(decoder)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_LOCALDB:
                if self._localmap is not None:
                    raise LowlevelError("Pre-existing local scope when restoring: " + self._name)
                newMap = ScopeLocal(uid, stackid, self, self._glb)
                if symboltab is None or not hasattr(symboltab, "decodeScope"):
                    raise LowlevelError("Missing symbol table scope decoder")
                symboltab.decodeScope(decoder, newMap)
                self._localmap = newMap
            elif subId == ELEM_OVERRIDE:
                self.getOverride().decode(decoder, self._glb)
            elif subId == ELEM_PROTOTYPE:
                if self._localmap is None:
                    newMap = ScopeLocal(uid, stackid, self, self._glb)
                    if symboltab is not None and hasattr(symboltab, "attachScope"):
                        symboltab.attachScope(
                            newMap,
                            symboltab.getGlobalScope() if hasattr(symboltab, "getGlobalScope") else None,
                        )
                    self._localmap = newMap
                self._funcp.setScope(self._localmap, self._baseaddr + -1)
                self._funcp.decode(decoder, self._glb)
            elif subId == ELEM_JUMPTABLELIST:
                self.decodeJumpTable(decoder)
            else:
                decoder.skipElement()
        decoder.closeElement(elemId)

        if self._localmap is None:
            newMap = ScopeLocal(uid, stackid, self, self._glb)
            if symboltab is not None and hasattr(symboltab, "attachScope"):
                symboltab.attachScope(
                    newMap,
                    symboltab.getGlobalScope() if hasattr(symboltab, "getGlobalScope") else None,
                )
            self._localmap = newMap
            self._funcp.setScope(self._localmap, self._baseaddr + -1)
        self._localmap.resetLocalWindow()
        return uid

    def encodeTree(self, encoder) -> None:
        """Encode the p-code tree (varnodes, ops, blocks, edges) to stream.

        C++ ref: ``Funcdata::encodeTree``
        """
        from ghidra.core.marshal import (
            ELEM_AST, ELEM_VARNODES, ELEM_BLOCK, ELEM_BLOCKEDGE,
            ATTRIB_INDEX,
        )
        from ghidra.core.space import IPTR_IOP
        encoder.openElement(ELEM_AST)

        # Encode all varnodes grouped by address space
        encoder.openElement(ELEM_VARNODES)
        for i in range(self._glb.numSpaces()):
            base = self._glb.getSpace(i)
            if base is None or base.getType() == IPTR_IOP:
                continue
            beginiter = self._vbank.beginLocSpace(base)
            enditer = self._vbank.endLocSpace(base)
            self.encodeVarnode(encoder, beginiter, enditer)
        encoder.closeElement(ELEM_VARNODES)

        # Encode each basic block with its ops
        for i in range(self._bblocks.getSize()):
            bs = self._bblocks.getBlock(i)
            encoder.openElement(ELEM_BLOCK)
            encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex())
            bs.encodeBody(encoder)
            for op in bs.getOpList():
                op.encode(encoder)
            encoder.closeElement(ELEM_BLOCK)

        # Encode edges for blocks that have incoming edges
        for i in range(self._bblocks.getSize()):
            bs = self._bblocks.getBlock(i)
            if bs.sizeIn() == 0:
                continue
            encoder.openElement(ELEM_BLOCKEDGE)
            encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex())
            bs.encodeEdges(encoder)
            encoder.closeElement(ELEM_BLOCKEDGE)

        encoder.closeElement(ELEM_AST)

    def encodeHigh(self, encoder) -> None:
        """Encode all HighVariables to stream.

        C++ ref: ``Funcdata::encodeHigh``
        """
        from ghidra.core.marshal import ELEM_HIGHLIST
        if not self.isHighOn():
            return
        encoder.openElement(ELEM_HIGHLIST)
        for vn in self._vbank.beginLoc():
            if vn.isAnnotation():
                continue
            high = vn.getHigh()
            if high.isMark():
                continue
            high.setMark()
            high.encode(encoder)
        for vn in self._vbank.beginLoc():
            if not vn.isAnnotation():
                vn.getHigh().clearMark()
        encoder.closeElement(ELEM_HIGHLIST)

    def encodeJumpTable(self, encoder) -> None:
        """Encode jump-tables to stream.

        C++ ref: ``Funcdata::encodeJumpTable``
        """
        from ghidra.core.marshal import ELEM_JUMPTABLELIST
        if not hasattr(self, '_jumpvec') or not self._jumpvec:
            return
        encoder.openElement(ELEM_JUMPTABLELIST)
        for jt in self._jumpvec:
            jt.encode(encoder)
        encoder.closeElement(ELEM_JUMPTABLELIST)

    def decodeJumpTable(self, decoder) -> None:
        """Decode jump-tables from a stream.

        C++ ref: ``Funcdata::decodeJumpTable``
        """
        from ghidra.core.marshal import ELEM_JUMPTABLELIST
        from ghidra.analysis.jumptable import JumpTable
        elemId = decoder.openElement(ELEM_JUMPTABLELIST)
        while decoder.peekElement() != 0:
            jt = JumpTable(self._glb)
            jt.decode(decoder)
            self._jumpvec.append(jt)
        decoder.closeElement(elemId)

    # --- Data-flow / transformation helpers ---

    def syncVarnodesWithSymbols(self, lm, updateDatatypes: bool,
                                 unmappedAliasCheck: bool) -> bool:
        """Synchronize Varnode properties with their Symbol overlaps.

        For every Varnode in the local scope's address space, find any
        overlapping SymbolEntry, update the Varnode's flags (mapped,
        addrtied, nolocalalias, etc.) and optionally its data-type.

        C++ ref: ``Funcdata::syncVarnodesWithSymbols``
        """
        from ghidra.types.datatype import TYPE_UNKNOWN

        updateoccurred = False
        vnlist = list(self.beginLoc(lm.getSpaceId()))
        i = 0
        while i < len(vnlist):
            vnexemplar = vnlist[i]
            # Collect all varnodes at same size/addr
            group = [vnexemplar]
            j = i + 1
            while j < len(vnlist) and vnlist[j].getSize() == vnexemplar.getSize() and vnlist[j].getAddr() == vnexemplar.getAddr():
                group.append(vnlist[j])
                j += 1
            entry = lm.findOverlap(vnexemplar.getAddr(), vnexemplar.getSize())
            ct = None
            if entry is not None:
                fl = entry.getAllFlags()
                if entry.getSize() >= vnexemplar.getSize():
                    if updateDatatypes:
                        ct = entry.getSizedType(vnexemplar.getAddr(), vnexemplar.getSize())
                        if ct is not None and ct.getMetatype() == TYPE_UNKNOWN:
                            _sync_debug_log(vnexemplar, "candidate_type_filtered=unknown")
                            ct = None
                else:
                    fl &= ~(Varnode.typelock | Varnode.namelock)
                _sync_debug_log(
                    vnexemplar,
                    "path=entry "
                    f"usepoint={vnexemplar.getUsePoint(self)} "
                    f"entry_addr={entry.getAddr()} "
                    f"entry_size={entry.getSize()} "
                    f"entry_sym={getattr(entry.getSymbol(), 'name', '?')} "
                    f"entry_addrtied={int(entry.isAddrTied())} "
                    f"entry_use={_sync_debug_rangelist(entry.getUseLimit())} "
                    f"fl={fl:#x} unmappedAliasCheck={int(unmappedAliasCheck)}",
                )
            else:
                in_scope = False
                is_unmapped_unaliased = False
                if lm.inScope(vnexemplar.getAddr(), vnexemplar.getSize(), vnexemplar.getUsePoint(self)):
                    in_scope = True
                    fl = Varnode.mapped | Varnode.addrtied
                elif unmappedAliasCheck:
                    is_unmapped_unaliased = lm.isUnmappedUnaliased(vnexemplar)
                    fl = Varnode.nolocalalias if is_unmapped_unaliased else 0
                else:
                    fl = 0
                _sync_debug_log(
                    vnexemplar,
                    "path=no_entry "
                    f"usepoint={vnexemplar.getUsePoint(self)} "
                    f"in_scope={int(in_scope)} "
                    f"is_unmapped_unaliased={int(is_unmapped_unaliased)} "
                    f"fl={fl:#x} unmappedAliasCheck={int(unmappedAliasCheck)}",
                )
            if self.syncVarnodesWithSymbol(group, fl, ct):
                updateoccurred = True
                _sync_debug_log(vnexemplar, f"sync_applied=1 post_flags={vnexemplar.getFlags():#x}")
            else:
                _sync_debug_log(vnexemplar, f"sync_applied=0 post_flags={vnexemplar.getFlags():#x}")
            i = j
        return updateoccurred

    def transferVarnodeProperties(self, vn, newVn, lsbOffset: int) -> None:
        """Transfer directwrite, addrforce, and consume properties.

        The consume mask is shifted right by lsbOffset bytes, with high bits
        filled in, and masked to the new Varnode's size.

        C++ ref: ``Funcdata::transferVarnodeProperties``
        """
        uintb_mask = (1 << 64) - 1
        newConsume = uintb_mask
        if lsbOffset < 8:
            fillBits = 0
            if lsbOffset != 0:
                fillBits = newConsume << (8 * (8 - lsbOffset))
            oldConsume = vn.getConsume()
            mask = (1 << (8 * min(newVn.getSize(), 8))) - 1 if newVn.getSize() > 0 else 0
            newConsume = ((oldConsume >> (8 * lsbOffset)) | fillBits) & mask
        vnFlags = vn.getFlags() & (Varnode.directwrite | Varnode.addrforce)
        newVn.setFlags(vnFlags)
        newVn.setConsume(newConsume)

    def fillinReadOnly(self, vn) -> bool:
        """Replace the given Varnode with its (constant) value in the load image.

        C++ ref: ``Funcdata::fillinReadOnly``
        """
        from ghidra.arch.loadimage import DataUnavailError

        if vn.isWritten():
            defop = vn.getDef()
            if defop.isMarker():
                defop.setAdditionalFlag(PcodeOp.warning)
            elif not defop.isWarning():
                defop.setAdditionalFlag(PcodeOp.warning)
                if (not vn.isAddrForce()) or (not vn.hasNoDescend()):
                    msg = (
                        f"Read-only address ({vn.getSpace().getName()},{vn.getAddr().printRaw()}) is written"
                    )
                    self.warning(msg, defop.getAddr())
            return False

        if vn.getSize() > 8:
            return False

        buf = bytearray(vn.getSize())
        try:
            self._glb.loader.loadFill(buf, vn.getSize(), vn.getAddr())
        except DataUnavailError:
            vn.clearFlags(Varnode.readonly)
            return True

        res = 0
        if vn.getSpace().isBigEndian():
            for i in range(vn.getSize()):
                res <<= 8
                res |= buf[i]
        else:
            for i in range(vn.getSize() - 1, -1, -1):
                res <<= 8
                res |= buf[i]

        changemade = False
        locktype = vn.getType() if vn.isTypeLock() else None
        for op in list(vn.beginDescend()):
            slot = op.getSlot(vn)
            if op.isMarker():
                if op.code() != OpCode.CPUI_INDIRECT or slot != 0:
                    continue
                outvn = op.getOut()
                if outvn.getAddr() == vn.getAddr():
                    continue
                self.opRemoveInput(op, 1)
                self.opSetOpcode(op, OpCode.CPUI_COPY)
            cvn = self.newConstant(vn.getSize(), res)
            if locktype is not None:
                cvn.updateType(locktype, True, True)
            self.opSetInput(op, cvn, slot)
            changemade = True
        return changemade

    def replaceVolatile(self, vn) -> bool:
        """Replace accesses of the given Varnode with volatile operations.

        The Varnode is assumed not fully linked. The read or write action is
        modeled by inserting a special user op (CALLOTHER) that represents
        the action. The given Varnode is replaced by a temporary Varnode
        within the data-flow, and the original address becomes a parameter.

        C++ ref: ``Funcdata::replaceVolatile``
        """
        from ghidra.arch.userop import UserPcodeOp
        from ghidra.core.error import LowlevelError

        if vn.isWritten():
            vw_op = self._glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_WRITE)
            if not vn.hasNoDescend():
                raise LowlevelError("Volatile memory was propagated")
            defop = vn.getDef()
            newop = self.newOp(3, defop.getAddr())
            self.opSetOpcode(newop, OpCode.CPUI_CALLOTHER)
            self.opSetInput(newop, self.newConstant(4, vw_op.getIndex()), 0)
            annoteVn = self.newCodeRef(vn.getAddr())
            annoteVn.setFlags(Varnode.volatil)
            self.opSetInput(newop, annoteVn, 1)
            tmp = self.newUnique(vn.getSize())
            self.opSetOutput(defop, tmp)
            self.opSetInput(newop, tmp, 2)
            self.opInsertAfter(newop, defop)
        else:
            vr_op = self._glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_READ)
            if vn.hasNoDescend():
                return False
            readop = vn.loneDescend()
            if readop is None:
                raise LowlevelError("Volatile memory value used more than once")
            newop = self.newOp(2, readop.getAddr())
            self.opSetOpcode(newop, OpCode.CPUI_CALLOTHER)
            tmp = self.newUniqueOut(vn.getSize(), newop)
            self.opSetInput(newop, self.newConstant(4, vr_op.getIndex()), 0)
            annoteVn = self.newCodeRef(vn.getAddr())
            annoteVn.setFlags(Varnode.volatil)
            self.opSetInput(newop, annoteVn, 1)
            self.opSetInput(readop, tmp, readop.getSlot(vn))
            self.opInsertBefore(newop, readop)
            if vr_op.getDisplay() != 0:
                newop.setHoldOutput()
        if vn.isTypeLock():
            newop.setAdditionalFlag(PcodeOp.special_prop)
        return True

    def remapVarnode(self, vn, sym, usepoint) -> None:
        """Remap a Symbol to a given Varnode using the local scope.

        Any previous links between Symbol and Varnode are removed, then
        a new mapping is created in the local scope.

        C++ ref: ``Funcdata::remapVarnode``
        """
        vn.clearSymbolLinks()
        entry = self._localmap.remapSymbol(sym, vn.getAddr(), usepoint)
        vn.setSymbolEntry(entry)

    def remapDynamicVarnode(self, vn, sym, usepoint, hashval) -> None:
        """Remap a Symbol to a Varnode using a new dynamic mapping.

        C++ ref: ``Funcdata::remapDynamicVarnode``
        """
        vn.clearSymbolLinks()
        entry = self._localmap.remapSymbolDynamic(sym, hashval, usepoint)
        vn.setSymbolEntry(entry)

    def newExtendedConstant(self, s: int, val, op):
        """Construct a constant Varnode up to 128 bits using INT_ZEXT or PIECE.

        If size <= 8, returns a normal constant. Otherwise, if the high
        64-bit chunk is zero, uses INT_ZEXT; otherwise uses PIECE to
        combine two 64-bit halves.

        C++ ref: ``Funcdata::newExtendedConstant``
        """
        if isinstance(val, (list, tuple)):
            lo = val[0]
            hi = val[1] if len(val) > 1 else 0
        else:
            lo = val
            hi = 0
        if s <= 8:
            return self.newConstant(s, lo)
        if hi == 0:
            extOp = self.newOp(1, op.getAddr())
            self.opSetOpcode(extOp, OpCode.CPUI_INT_ZEXT)
            newConstVn = self.newUniqueOut(s, extOp)
            self.opSetInput(extOp, self.newConstant(8, lo), 0)
            self.opInsertBefore(extOp, op)
        else:
            pieceOp = self.newOp(2, op.getAddr())
            self.opSetOpcode(pieceOp, OpCode.CPUI_PIECE)
            newConstVn = self.newUniqueOut(s, pieceOp)
            self.opSetInput(pieceOp, self.newConstant(8, hi), 0)  # Most significant
            self.opSetInput(pieceOp, self.newConstant(8, lo), 1)  # Least significant
            self.opInsertBefore(pieceOp, op)
        return newConstVn

    def adjustInputVarnodes(self, addr, sz: int) -> None:
        """Adjust input Varnodes contained in the given range.

        All input Varnodes in the range are replaced by SUBPIECE ops from
        a single new input Varnode covering the whole range.

        C++ ref: ``Funcdata::adjustInputVarnodes``
        """
        from ghidra.core.error import LowlevelError

        endaddr = addr + (sz - 1)
        inlist = []
        for vn in self._vbank.beginDefFlags(Varnode.input):
            vnaddr = vn.getAddr()
            if vnaddr.getSpace() is not addr.getSpace():
                continue
            if vnaddr < addr or vnaddr > endaddr:
                continue
            if vn.getOffset() + (vn.getSize() - 1) > endaddr.getOffset():
                raise LowlevelError("Cannot properly adjust input varnodes")
            inlist.append(vn)
        for i, vn in enumerate(inlist):
            sa = addr.justifiedContain(sz, vn.getAddr(), vn.getSize(), False)
            if not vn.isInput() or sa < 0 or sz <= vn.getSize():
                raise LowlevelError("Bad adjustment to input varnode")
            subop = self.newOp(2, self.getAddress())
            self.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subop, self.newConstant(4, sa), 1)
            newvn = self.newVarnodeOut(vn.getSize(), vn.getAddr(), subop)
            bl = self._bblocks.getBlock(0)
            self.opInsertBegin(subop, bl)
            self.totalReplace(vn, newvn)
            self.deleteVarnode(vn)
            inlist[i] = newvn
        invn = self.newVarnode(sz, addr)
        invn = self.setInputVarnode(invn)
        invn.setWriteMask()
        for newvn in inlist:
            op = newvn.getDef()
            if op is not None:
                self.opSetInput(op, invn, 0)

    def findDisjointCover(self, vn, sz=None):
        """Find the native disjoint-cover range for the given Varnode."""
        addr = vn.getAddr()
        endaddr = addr + vn.getSize()
        loclist = list(self._vbank.beginLoc()) if hasattr(self._vbank, "beginLoc") else [vn]

        vnindex = None
        for idx, curvn in enumerate(loclist):
            if curvn is vn:
                vnindex = idx
                break
        if vnindex is None:
            loclist = [vn]
            vnindex = 0

        for idx in range(vnindex - 1, -1, -1):
            curvn = loclist[idx]
            curend = curvn.getAddr() + curvn.getSize()
            if curend <= addr:
                break
            addr = curvn.getAddr()

        for idx in range(vnindex, len(loclist)):
            curvn = loclist[idx]
            if endaddr <= curvn.getAddr():
                break
            endaddr = curvn.getAddr() + curvn.getSize()

        actual_sz = endaddr.getOffset() - addr.getOffset()
        if sz is not None:
            if len(sz) == 0:
                sz.append(actual_sz)
            else:
                sz[0] = actual_sz
        return addr

    def checkForLanedRegister(self, sz: int, addr) -> None:
        """Check if a storage range is a potential laned register.

        If so, record the storage with the matching laned register record
        in the lanedMap.

        C++ ref: ``Funcdata::checkForLanedRegister``
        """
        lanedReg = self._glb.getLanedRegister(addr, sz)
        if lanedReg is None:
            return
        key = VarnodeData(addr.getSpace(), addr.getOffset(), sz)
        self._lanedMap[key] = lanedReg

    def recoverJumpTable(self, partial, op, flow, mode_ref):
        """Recover control-flow destinations for a BRANCHIND.

        If an existing and complete JumpTable exists for the BRANCHIND, it is
        returned immediately. Otherwise an attempt is made to analyze the
        current partial function and recover the set of destination addresses,
        which if successful will be returned as a new JumpTable object.

        C++ ref: ``Funcdata::recoverJumpTable``

        Args:
            partial: The Funcdata copy used for jump-table recovery.
            op: The BRANCHIND PcodeOp.
            flow: Current FlowInfo for this function.
            mode_ref: A list [mode] that receives the JumpTable.RecoveryMode.

        Returns:
            The recovered JumpTable, or None on failure.
        """
        from ghidra.analysis.jumptable import JumpTable

        def _normalize_mode(mode):
            if isinstance(mode, str):
                return getattr(JumpTable.RecoveryMode, mode, mode)
            return mode

        mode_ref[0] = JumpTable.RecoveryMode.success

        # Search for pre-existing jumptable
        jt = self.linkJumpTable(op)
        if jt is not None:
            if not jt.isOverride():
                if not jt.isPartial():
                    return jt  # Previously calculated (NOT override, NOT incomplete)
            # Recover based on override / partial information
            mode_ref[0] = _normalize_mode(self.stageJumpTable(partial, jt, op, flow))
            if mode_ref[0] != JumpTable.RecoveryMode.success:
                return None
            jt.setIndirectOp(op)  # Relink table back to original op
            return jt

        if (self._flags & Funcdata.jumptablerecovery_dont) != 0:
            return None  # Explicitly told not to recover jumptables

        mode_ref[0] = _normalize_mode(self.earlyJumpTableFail(op))
        if mode_ref[0] != JumpTable.RecoveryMode.success:
            return None

        # Create a trial JumpTable
        trialjt = JumpTable(self._glb)
        mode_ref[0] = _normalize_mode(self.stageJumpTable(partial, trialjt, op, flow))
        if mode_ref[0] != JumpTable.RecoveryMode.success:
            return None

        # Make the jumptable permanent
        jt = JumpTable(trialjt)
        self._jumpvec.append(jt)
        jt.setIndirectOp(op)  # Relink table back to original op
        return jt

    def earlyJumpTableFail(self, op):
        """Backtrack from the BRANCHIND, looking for ops that might affect the destination.

        If a CALLOTHER, which is not injected/inlined in some way, is in the flow path of
        the destination calculation, we know the jump-table analysis will fail and the
        failure mode is returned.

        C++ ref: ``Funcdata::earlyJumpTableFail``

        Returns:
            `JumpTable.RecoveryMode.success` if there is no early failure, or the failure
            mode otherwise.
        """
        from ghidra.analysis.jumptable import JumpTable
        from ghidra.arch.userop import UserPcodeOp
        from ghidra.ir.op import PcodeOp as PcOp

        vn = op.getIn(0)
        countMax = 8
        dead_ops = list(self._obank.beginDead())
        try:
            idx = dead_ops.index(op)
        except ValueError:
            return JumpTable.RecoveryMode.success
        while idx > 0:
            if vn.getSize() == 1:
                return JumpTable.RecoveryMode.success
            countMax -= 1
            if countMax < 0:
                return JumpTable.RecoveryMode.success
            idx -= 1
            cur = dead_ops[idx]
            outvn = cur.getOut()
            outhit = False
            if outvn is not None:
                outhit = vn.intersects(outvn)
            evaltype = cur.getEvalType()
            if evaltype == PcOp.special:
                if cur.isCall():
                    opc = cur.code()
                    if opc == OpCode.CPUI_CALLOTHER:
                        uid = int(cur.getIn(0).getOffset())
                        utype = self._glb.userops.getOp(uid).getType()
                        if (
                            utype == UserPcodeOp.injected
                            or utype == UserPcodeOp.jumpassist
                            or utype == UserPcodeOp.segment
                        ):
                            return JumpTable.RecoveryMode.success
                        if outhit:
                            return JumpTable.RecoveryMode.fail_callother
                    else:
                        return JumpTable.RecoveryMode.success
                elif cur.isBranch():
                    return JumpTable.RecoveryMode.success
                else:
                    if cur.code() == OpCode.CPUI_STORE:
                        return JumpTable.RecoveryMode.success
                    if outhit:
                        return JumpTable.RecoveryMode.success
            elif evaltype == PcOp.unary:
                if outhit:
                    invn = cur.getIn(0)
                    if invn.getSize() != vn.getSize():
                        return JumpTable.RecoveryMode.success
                    vn = invn
            elif evaltype == PcOp.binary:
                if outhit:
                    opc = cur.code()
                    if opc not in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB, OpCode.CPUI_INT_XOR):
                        return JumpTable.RecoveryMode.success
                    if not cur.getIn(1).isConstant():
                        return JumpTable.RecoveryMode.success
                    invn = cur.getIn(0)
                    if invn.getSize() != vn.getSize():
                        return JumpTable.RecoveryMode.success
                    vn = invn
            else:
                if outhit:
                    return JumpTable.RecoveryMode.success
        return JumpTable.RecoveryMode.success

    def testForReturnAddress(self, vn) -> bool:
        """Test if the given Varnode traces back to the return address input.

        Walk backwards through INDIRECT, COPY, and INT_AND (alignment mask)
        ops to see if the ultimate source is the default return address input.

        C++ ref: ``Funcdata::testForReturnAddress``
        """
        retaddr = self.getArch().defaultReturnAddr
        if retaddr.space is None:
            return False
        while vn.isWritten():
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_INDIRECT or opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
            elif opc == OpCode.CPUI_INT_AND:
                if not op.getIn(1).isConstant():
                    return False
                vn = op.getIn(0)
            else:
                return False
        if vn.getSpace() != retaddr.space or vn.getOffset() != retaddr.offset or vn.getSize() != retaddr.size:
            return False
        return vn.isInput()

    def getInternalString(self, buf, size, ptrType, readOp):
        """Create a Varnode that will display as a string constant.

        The raw data for the encoded string is given. If it encodes a legal
        string, the string is stored via StringManager, and a CALLOTHER
        stringdata user-op is created whose output Varnode is returned.

        C++ ref: ``Funcdata::getInternalString``
        """
        from ghidra.arch.userop import UserPcodeOp
        from ghidra.types.datatype import TYPE_PTR

        if ptrType.getMetatype() != TYPE_PTR:
            return None
        charType = ptrType.getPtrTo()
        addr = readOp.getAddr()
        hashval = self._glb.stringManager.registerInternalStringData(addr, buf, size, charType)
        if hashval == 0:
            return None
        self._glb.userops.registerBuiltin(UserPcodeOp.BUILTIN_STRINGDATA)
        stringOp = self.newOp(2, addr)
        self.opSetOpcode(stringOp, OpCode.CPUI_CALLOTHER)
        stringOp.clearFlag(PcodeOp.call)
        self.opSetInput(stringOp, self.newConstant(4, UserPcodeOp.BUILTIN_STRINGDATA), 0)
        self.opSetInput(stringOp, self.newConstant(8, hashval), 1)
        resVn = self.newUniqueOut(ptrType.getSize(), stringOp)
        resVn.updateType(ptrType, True, False)
        self.opInsertBefore(stringOp, readOp)
        return resVn

    def moveRespectingCover(self, op, lastOp) -> bool:
        """Move \b op past \b lastOp, only crossing COPY/CAST ops, respecting covers.

        Uses HighVariable.markExpression to identify all HighVariables
        read by the expression rooted at \b op's output. If any crossed
        COPY/CAST writes to a marked High, there is a direct interference
        and the move is aborted. If the expression contains address-tied
        reads (typeVal != 0) and a crossed op writes an address-tied varnode,
        the move is also aborted (indirect interference).

        C++ ref: ``Funcdata::moveRespectingCover``
        """
        if op is lastOp:
            return True
        if op.isCall():
            return False
        prevOp = None
        if op.code() == OpCode.CPUI_CAST:
            vn = op.getIn(0)
            if not vn.isExplicit():
                if not vn.isWritten():
                    return False
                prevOp = vn.getDef()
                if prevOp.isCall():
                    return False
                if op.previousOp() is not prevOp:
                    return False
        rootvn = op.getOut()

        # Mark expression variables for interference detection
        highList = []
        from ghidra.ir.variable import HighVariable
        typeVal = HighVariable.markExpression(rootvn, highList)

        curOp = op
        while curOp is not lastOp:
            nextOp = curOp.nextOp()
            opc = nextOp.code()
            if opc != OpCode.CPUI_COPY and opc != OpCode.CPUI_CAST:
                break
            if rootvn is nextOp.getIn(0):
                break  # Data-flow order dependence
            copyVn = nextOp.getOut()
            if copyVn.getHigh().isMark():
                break  # Direct interference: COPY writes what original op reads
            if typeVal != 0 and copyVn.isAddrTied():
                break  # Possible indirect interference
            curOp = nextOp

        # Clear marks on expression
        for h in highList:
            h.clearMark()

        if curOp is lastOp:
            self.opUninsert(op)
            self.opInsertAfter(op, lastOp)
            if prevOp is not None:
                self.opUninsert(prevOp)
                self.opInsertAfter(prevOp, lastOp)
            return True
        return False

    def forceFacingType(self, parent, fieldNum: int, op, slot: int) -> None:
        """Force a specific field resolution for a data-type on a PcodeOp edge.

        C++ ref: ``Funcdata::forceFacingType``
        """
        baseType = parent
        from ghidra.types.datatype import TYPE_PTR
        from ghidra.types.resolve import ResolvedUnion
        if baseType.getMetatype() == TYPE_PTR:
            baseType = baseType.getPtrTo()
        if parent.isPointerRel():
            parent = self._glb.types.getTypePointer(parent.getSize(), baseType, parent.getWordSize())
        resolve = ResolvedUnion(parent, fieldNum, self._glb.types)
        self.setUnionField(parent, op, slot, resolve)

    def inheritResolution(self, parent, op, slot: int, oldOp, oldSlot: int) -> int:
        """Copy a read/write facing resolution for a data-type from one PcodeOp to another.

        C++ ref: ``Funcdata::inheritResolution``
        """
        if self._unionMap is None:
            return -1
        resolve = self._unionMap.getUnionField(parent, oldOp, oldSlot)
        if resolve is None:
            return -1
        self.setUnionField(parent, op, slot, resolve)
        return resolve.getFieldNum()

    def markReturnCopy(self, op) -> None:
        op.setFlag(PcodeOp.return_copy)

    def numCallSpecs(self) -> int:
        return len(self._qlst)

    def getJumpTableByIndex(self, i: int):
        """Get JumpTable by list index."""
        if 0 <= i < len(self._jumpvec):
            return self._jumpvec[i]
        return None

    def getHighCount(self) -> int:
        return self._highcount if hasattr(self, '_highcount') else 0

    def setHighCount(self, val: int) -> None:
        self._highcount = val

    def hasMutualExclusion(self) -> bool:
        return False

    def getMinimumLanedSize(self) -> int:
        return self._minLanedSize if hasattr(self, '_minLanedSize') else 0

    def setMinimumLanedSize(self, val: int) -> None:
        self._minLanedSize = val

    def getDecompileMaxInstructions(self) -> int:
        return self._decomp_max_inst if hasattr(self, '_decomp_max_inst') else 0

    def setDecompileMaxInstructions(self, val: int) -> None:
        self._decomp_max_inst = val

    def getRestartPending(self) -> bool:
        return self._restart_pending if hasattr(self, '_restart_pending') else False

    def getMaxOpcodeIndex(self) -> int:
        return self._maxopcodeindex if hasattr(self, '_maxopcodeindex') else 0

    def getCastPhase(self) -> int:
        return self._cast_phase if hasattr(self, '_cast_phase') else 0

    def setCastPhase(self, val: int) -> None:
        self._cast_phase = val

    def getHighLevelCount(self) -> int:
        return self._highlevelcount if hasattr(self, '_highlevelcount') else 0

    def getJumpTableCount(self) -> int:
        return self._jumptablecount if hasattr(self, '_jumptablecount') else 0

    def getNumCalls(self) -> int:
        return len(self._qlst) if hasattr(self, '_qlst') else 0

    def getNumHighVariables(self) -> int:
        return self._numHighVars if hasattr(self, '_numHighVars') else 0

    def getCallGraphNode(self):
        return self._callGraphNode if hasattr(self, '_callGraphNode') else None

    def setCallGraphNode(self, node) -> None:
        self._callGraphNode = node

    def getBaseOffset(self) -> int:
        return self._baseoffset if hasattr(self, '_baseoffset') else 0

    def getSwitchCount(self) -> int:
        return self._switchcount if hasattr(self, '_switchcount') else 0

    def getOverrideCount(self) -> int:
        return self._overridecount if hasattr(self, '_overridecount') else 0

    def getReturnAddr(self):
        return self._returnaddr if hasattr(self, '_returnaddr') else None

    # --- Print / debug ---

    def printRaw(self, s=None):
        """Print raw p-code op descriptions.

        If no basic blocks exist, prints all raw ops from the op bank.
        Otherwise delegates to bblocks.printRaw() which prints blocks
        with their edges.

        C++ ref: ``Funcdata::printRaw``
        """
        import io

        from ghidra.core.error import RecovError

        owns_stream = s is None
        out = io.StringIO() if owns_stream else s
        if self._bblocks.getSize() == 0:
            if self._obank.empty() if hasattr(self._obank, 'empty') else True:
                raise RecovError("No operations to print")
            out.write("Raw operations:\n")
            for op in self._obank.beginAll() if hasattr(self._obank, 'beginAll') else []:
                out.write(f"{op.getSeqNum()}:\t")
                out.write(op.printRaw() if hasattr(op, 'printRaw') else str(op))
                out.write("\n")
        else:
            if hasattr(self._bblocks, 'printRaw'):
                self._bblocks.printRaw(out)
            else:
                for i in range(self._bblocks.getSize()):
                    bl = self._bblocks.getBlock(i)
                    if isinstance(bl, BlockBasic):
                        out.write(f"  Block {bl.getIndex()} ({bl.getStart()} - {bl.getStop()}):\n")
                        for op in bl.getOpList():
                            out.write(f"    {op.printRaw()}\n")
        if owns_stream:
            return out.getvalue()
        return None

    def find(self, addr) -> Optional[Varnode]:
        """Find a Varnode by address."""
        return self._vbank.find(addr) if hasattr(self._vbank, 'find') else None

    # --- Debug methods (C++ OPACTION_DEBUG) ---

    def debugActivate(self) -> None:
        """Activate debug mode for the current action application."""
        if self._opactdbg_on:
            self._opactdbg_active = True

    def debugDeactivate(self) -> None:
        """Deactivate debug mode."""
        self._opactdbg_active = False

    def debugEnable(self) -> None:
        """Enable the debug console."""
        self._opactdbg_on = True
        self._opactdbg_count = 0

    def debugDisable(self) -> None:
        """Disable the debug console."""
        self._opactdbg_on = False

    def debugBreak(self) -> bool:
        """Check if a debug breakpoint has been hit."""
        return self._opactdbg_on and self._opactdbg_breakon

    def debugHandleBreak(self) -> None:
        """Handle a debug breakpoint."""
        self._opactdbg_breakon = False

    def debugSetBreak(self, count: int) -> None:
        """Set the debug break hit count."""
        self._opactdbg_breakcount = count

    def debugSetRange(
        self,
        pclow,
        pchigh,
        uqlow: int = 0xFFFFFFFFFFFFFFFF,
        uqhigh: int = 0xFFFFFFFFFFFFFFFF,
    ) -> None:
        """Set a debug address range."""
        self._opactdbg_on = True
        self._opactdbg_pclow.append(pclow)
        self._opactdbg_pchigh.append(pchigh)
        self._opactdbg_uqlow.append(uqlow)
        self._opactdbg_uqhigh.append(uqhigh)

    def debugCheckRange(self, op) -> bool:
        """Check if an op falls in one of the configured debug ranges."""
        size = len(self._opactdbg_pclow)
        for i in range(size):
            if not self._opactdbg_pclow[i].isInvalid():
                if op.getAddr() < self._opactdbg_pclow[i]:
                    continue
                if self._opactdbg_pchigh[i] < op.getAddr():
                    continue
            if self._opactdbg_uqlow[i] != 0xFFFFFFFFFFFFFFFF:
                if self._opactdbg_uqlow[i] > op.getTime():
                    continue
                if self._opactdbg_uqhigh[i] < op.getTime():
                    continue
            return True
        return False

    def debugPrintRange(self, count: int) -> None:
        """Print the debug range."""
        parts = []
        if not self._opactdbg_pclow[count].isInvalid():
            parts.append(
                f"PC = ({self._opactdbg_pclow[count].printRaw()},{self._opactdbg_pchigh[count].printRaw()})  "
            )
        else:
            parts.append("entire function ")
        if self._opactdbg_uqlow[count] != 0xFFFFFFFFFFFFFFFF:
            parts.append(f"unique = ({self._opactdbg_uqlow[count]:x},{self._opactdbg_uqhigh[count]:x})")
        self._glb.printDebug("".join(parts))

    def debugModCheck(self, op) -> None:
        """Check if an op modification should trigger debug output."""
        if op.isModified():
            return
        if not self.debugCheckRange(op):
            return
        op.setAdditionalFlag(PcodeOp.modified)
        self._modify_list.append(op)
        self._modify_before.append(op.printDebug())

    def debugModClear(self) -> None:
        """Clear the modification check state."""
        for op in self._modify_list:
            op.clearAdditionalFlag(PcodeOp.modified)
        self._modify_list.clear()
        self._modify_before.clear()
        self._opactdbg_active = False

    def debugModPrint(self, actionname: str) -> None:
        """Print a debug message for a modification."""
        if not self._opactdbg_active:
            return
        self._opactdbg_active = False
        if not self._modify_list:
            return
        self._opactdbg_breakon |= self._opactdbg_count == self._opactdbg_breakcount
        lines = [f"DEBUG {self._opactdbg_count}: {actionname}"]
        self._opactdbg_count += 1
        for i, op in enumerate(self._modify_list):
            lines.append(self._modify_before[i])
            lines.append(f"   {op.printDebug()}")
            op.clearAdditionalFlag(PcodeOp.modified)
        self._modify_list.clear()
        self._modify_before.clear()
        self._glb.printDebug("\n".join(lines) + "\n")

    def debugClear(self) -> None:
        """Clear all debug state."""
        self._opactdbg_pclow.clear()
        self._opactdbg_pchigh.clear()
        self._opactdbg_uqlow.clear()
        self._opactdbg_uqhigh.clear()

    def debugSize(self) -> int:
        """Return the number of debug records."""
        return len(self._opactdbg_pclow)

    def __repr__(self) -> str:
        return (f"Funcdata({self._name!r} @ {self._baseaddr}, "
                f"varnodes={self._vbank.size()}, "
                f"blocks={self._bblocks.getSize()})")


class CloneBlockOps:
    """Clone p-code ops when splitting control-flow at a merge point.

    Used for duplicating either a whole basic block, or an expression
    subset within a basic block.

    C++ ref: ``funcdata.hh / funcdata_block.cc``
    """

    class ClonePair:
        def __init__(self, c: PcodeOp, o: PcodeOp) -> None:
            self.cloneOp = c
            self.origOp = o

    def __init__(self, fd: Funcdata) -> None:
        self.data: Funcdata = fd
        self.cloneList: List[CloneBlockOps.ClonePair] = []
        self.origToClone: dict = {}  # Map from original PcodeOp to clone

    def buildOpClone(self, op: PcodeOp) -> Optional[PcodeOp]:
        """Produce a skeleton copy of the given PcodeOp.

        C++ ref: CloneBlockOps::buildOpClone
        """
        from ghidra.core.error import LowlevelError

        if op.isBranch():
            if op.code() != OpCode.CPUI_BRANCH:
                raise LowlevelError("Cannot duplicate 2-way or n-way branch in nodeplit")
            return None
        dup = self.data.newOp(op.numInput(), op.getAddr())
        self.data.opSetOpcode(dup, op.code())
        fl = op._flags & (
            PcodeOp.startbasic
            | PcodeOp.nocollapse
            | PcodeOp.startmark
            | PcodeOp.nonprinting
            | PcodeOp.halt
            | PcodeOp.badinstruction
            | PcodeOp.unimplemented
            | PcodeOp.noreturn
            | PcodeOp.missing
            | PcodeOp.indirect_creation
            | PcodeOp.indirect_store
            | PcodeOp.no_indirect_collapse
            | PcodeOp.calculated_bool
            | PcodeOp.ptrflow
        )
        dup.setFlag(fl)
        afl = op._addlflags & (
            PcodeOp.special_prop
            | PcodeOp.special_print
            | PcodeOp.incidental_copy
            | PcodeOp.is_cpool_transformed
            | PcodeOp.stop_type_propagation
            | PcodeOp.store_unmapped
        )
        dup.setAdditionalFlag(afl)
        self.cloneList.append(CloneBlockOps.ClonePair(dup, op))
        self.origToClone[op] = dup
        return dup

    def buildVarnodeOutput(self, origOp: PcodeOp, cloneOp: PcodeOp) -> None:
        """Clone the output Varnode of the given op onto its clone.

        C++ ref: CloneBlockOps::buildVarnodeOutput
        """
        opvn = origOp.getOut()
        if opvn is None:
            return
        newvn = self.data.newVarnodeOut(opvn.getSize(), opvn.getAddr(), cloneOp)
        vflags = opvn.getFlags()
        vflags &= (Varnode.externref | Varnode.volatil | Varnode.incidental_copy |
                   Varnode.readonly | Varnode.persist | Varnode.addrtied |
                   Varnode.addrforce | Varnode.nolocalalias | Varnode.spacebase |
                   Varnode.indirect_creation | Varnode.return_address |
                   Varnode.precislo | Varnode.precishi | Varnode.incidental_copy)
        newvn.setFlags(vflags)
        aflags = opvn._addlflags & (Varnode.writemask | Varnode.ptrflow | Varnode.stack_store)
        newvn._addlflags |= aflags

    def patchInputs(self, inedge: int) -> None:
        """Set the input Varnodes of all cloned ops.

        C++ ref: CloneBlockOps::patchInputs
        """
        from ghidra.core.error import LowlevelError

        for pair in self.cloneList:
            origOp = pair.origOp
            cloneOp = pair.cloneOp
            if origOp.code() == OpCode.CPUI_MULTIEQUAL:
                cloneOp.setNumInputs(1)
                self.data.opSetOpcode(cloneOp, OpCode.CPUI_COPY)
                self.data.opSetInput(cloneOp, origOp.getIn(inedge), 0)
                self.data.opRemoveInput(origOp, inedge)
                if origOp.numInput() == 1:
                    self.data.opSetOpcode(origOp, OpCode.CPUI_COPY)
            elif origOp.code() == OpCode.CPUI_INDIRECT:
                raise LowlevelError("Can't clone INDIRECTs")
            elif origOp.isCall():
                raise LowlevelError("Can't clone CALLs")
            else:
                for i in range(cloneOp.numInput()):
                    origVn = origOp.getIn(i)
                    if origVn.isConstant():
                        cloneVn = origVn
                    elif origVn.isAnnotation():
                        cloneVn = self.data.newCodeRef(origVn.getAddr())
                    elif origVn.isFree():
                        raise LowlevelError("Can't clone free varnode")
                    else:
                        if origVn.isWritten():
                            defOp = origVn.getDef()
                            clonedDef = self.origToClone.get(defOp)
                            if clonedDef is not None:
                                cloneVn = clonedDef.getOut()
                            else:
                                cloneVn = origVn
                        else:
                            cloneVn = origVn
                    self.data.opSetInput(cloneOp, cloneVn, i)

    def cloneBlock(self, b: BlockBasic, bprime: BlockBasic, inedge: int) -> None:
        """Clone all p-code ops from a block into its copy.

        C++ ref: CloneBlockOps::cloneBlock
        """
        for origOp in b.getOpList():
            cloneOp = self.buildOpClone(origOp)
            if cloneOp is None:
                continue
            self.buildVarnodeOutput(origOp, cloneOp)
            self.data.opInsertEnd(cloneOp, bprime)
        self.patchInputs(inedge)

    def cloneExpression(self, ops: List[PcodeOp], followOp: PcodeOp) -> Varnode:
        """Clone p-code ops in an expression before followOp.

        C++ ref: CloneBlockOps::cloneExpression
        """
        from ghidra.core.error import LowlevelError

        cloneOp = None
        for origOp in ops:
            cloneOp = self.buildOpClone(origOp)
            if cloneOp is None:
                continue
            self.buildVarnodeOutput(origOp, cloneOp)
            self.data.opInsertBefore(cloneOp, followOp)
        if not self.cloneList:
            raise LowlevelError("No expression to clone")
        self.patchInputs(0)
        lastCloneOp = self.cloneList[-1].cloneOp
        return lastCloneOp.getOut()
