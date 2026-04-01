"""
ActionDeadCode implementation.
Corresponds to ActionDeadCode in coreaction.cc.
"""
from __future__ import annotations
from typing import List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, coveringmask, minimalmask, leastsigbit_set, uintbmasks
_IPTR_IOP_TYPE = 5  # SpaceType.IPTR_IOP — inline to avoid import + getType() call
from ghidra.transform.action import Action

# Hot-path constants: direct int values to avoid attribute lookup overhead
_VACCONSUME  = 0x04   # Varnode._addlflags: vacconsume
_LISCONSUME  = 0x08   # Varnode._addlflags: lisconsume
_CONSUME_FL  = 0x0C   # vacconsume | lisconsume combined
_VN_WRITTEN  = 0x10   # Varnode._flags: written
_VN_CONSTANT = 0x02   # Varnode._flags: constant
_VN_ADDRFORCE   = 0x100000  # Varnode.addrforce
_VN_DIRECTWRITE = 0x80000   # Varnode.directwrite
# Opcode integer constants (avoid OpCode.CPUI_xxx global lookups in hot loops)
_OPC_INT_MULT    = 32; _OPC_INT_ADD  = 19; _OPC_INT_SUB    = 20
_OPC_SUBPIECE    = 63; _OPC_PIECE    = 62; _OPC_INDIRECT   = 61
_OPC_COPY        =  1; _OPC_INT_NEG  = 25; _OPC_INT_XOR    = 26
_OPC_INT_AND     = 27; _OPC_INT_OR   = 28; _OPC_MULTIEQUAL = 60
_OPC_INT_ZEXT    = 17; _OPC_INT_SEXT = 18; _OPC_INT_LEFT   = 29
_OPC_INT_RIGHT   = 30; _OPC_INT_SRHT = 31; _OPC_INT_LESS   = 15
_OPC_INT_LESSEE  = 16; _OPC_INT_EQ   = 11; _OPC_INT_NEQ    = 12
_OPC_INSERT      = 70; _OPC_EXTRACT  = 71; _OPC_POPCOUNT   = 72
_OPC_LZCOUNT     = 73; _OPC_CALL     =  7; _OPC_CALLIND    =  8
_OPC_FLOAT_I2F   = 54; _OP_INDSRC_FL = 0x400  # PcodeOp.indirect_source

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


class ActionDeadCode(Action):
    """Dead code removal via consumed-bit propagation.

    C++ ref: ``ActionDeadCode`` in coreaction.cc
    """

    def __init__(self, g: str) -> None:
        super().__init__(0, "deadcode", g)

    def clone(self, gl):
        return ActionDeadCode(self._basegroup) if gl.contains(self._basegroup) else None

    # ------------------------------------------------------------------
    # pushConsumed  (C++ inline ActionDeadCode::pushConsumed)
    # ------------------------------------------------------------------
    @staticmethod
    def _pushConsumed(val: int, vn, worklist: List):
        if vn is None:
            return
        sz = vn._size
        cur = vn._consumed
        newval = (val | cur) & (uintbmasks[sz] if sz < 9 else 0xFFFFFFFFFFFFFFFF)
        af = vn._addlflags
        if newval == cur and af & _VACCONSUME:
            return
        vn._addlflags = af | _VACCONSUME
        if not (af & _LISCONSUME):
            vn._addlflags |= _LISCONSUME
            if vn._flags & _VN_WRITTEN:
                worklist.append(vn)
        vn._consumed = newval

    # ------------------------------------------------------------------
    # propagateConsumed  (C++ ActionDeadCode::propagateConsumed)
    # ------------------------------------------------------------------
    @staticmethod
    def _propagateConsumed(worklist: List, push):
        vn = worklist.pop()
        outc = vn._consumed
        vn._addlflags &= ~_LISCONSUME
        op = vn._def
        opc = op._opcode_enum
        ALL = 0xFFFFFFFFFFFFFFFF
        ins = op._inrefs

        if opc == _OPC_INT_MULT:
            b = coveringmask(outc)
            in1 = ins[1]
            if in1._flags & _VN_CONSTANT:
                ls = leastsigbit_set(in1._loc.offset)
                if ls >= 0:
                    sz = vn._size
                    a = ((uintbmasks[sz] if sz < 9 else ALL) >> ls) & b
                else:
                    a = 0
            else:
                a = b
            push(a, ins[0], worklist)
            push(b, in1, worklist)
        elif opc == _OPC_INT_ADD or opc == _OPC_INT_SUB:
            a = coveringmask(outc)
            push(a, ins[0], worklist)
            push(a, ins[1], worklist)
        elif opc == _OPC_SUBPIECE:
            sz = ins[1]._loc.offset
            if sz >= 8:
                a = 0
            else:
                a = outc << (sz * 8)
            if a == 0 and outc != 0 and ins[0]._size > 8:
                a = ALL
                a = a ^ (a >> 1)
            b = ALL if outc != 0 else 0
            push(a, ins[0], worklist)
            push(b, ins[1], worklist)
        elif opc == _OPC_PIECE:
            in1 = ins[1]
            sz = in1._size
            if vn._size > 8:
                if sz >= 8:
                    a = ALL
                    b = outc
                else:
                    a = (outc >> (sz * 8)) ^ (ALL << (8 * (8 - sz)))
                    b = outc ^ (a << (sz * 8))
            else:
                a = outc >> (sz * 8)
                b = outc ^ (a << (sz * 8))
            push(a, ins[0], worklist)
            push(b, in1, worklist)
        elif opc == _OPC_INDIRECT:
            push(outc, ins[0], worklist)
            iopvn = ins[1]
            iopvn_spc = iopvn._loc.base
            if iopvn_spc is not None and iopvn_spc._type == _IPTR_IOP_TYPE:
                indop = iopvn._iop_ref
                if indop is not None and not (indop._flags & 0x20):  # 0x20 = PcodeOp.dead
                    if indop._opcode_enum == _OPC_COPY:
                        outvn = indop._output
                        if outvn is not None:
                            res = outvn.characterizeOverlap(op._output)
                            if res > 0:
                                push(ALL, outvn, worklist)
                                indop._flags |= _OP_INDSRC_FL
                    else:
                        indop._flags |= _OP_INDSRC_FL
        elif opc == _OPC_COPY or opc == _OPC_INT_NEG:
            push(outc, ins[0], worklist)
        elif opc == _OPC_INT_XOR or opc == _OPC_INT_OR:
            push(outc, ins[0], worklist)
            push(outc, ins[1], worklist)
        elif opc == _OPC_INT_AND:
            in1 = ins[1]
            if in1._flags & _VN_CONSTANT:
                val = in1._loc.offset  # getOffset() inlined
                push(outc & val, ins[0], worklist)
                push(outc, in1, worklist)
            else:
                push(outc, ins[0], worklist)
                push(outc, in1, worklist)
        elif opc == _OPC_MULTIEQUAL:
            for inv in ins:
                push(outc, inv, worklist)
        elif opc == _OPC_INT_ZEXT:
            push(outc, ins[0], worklist)
        elif opc == _OPC_INT_SEXT:
            in0 = ins[0]
            sz0 = in0._size
            b = uintbmasks[sz0] if sz0 < 9 else ALL
            a = outc & b
            if outc > b:
                a |= (b ^ (b >> 1))
            push(a, in0, worklist)
        elif opc == _OPC_INT_LEFT:
            if ins[1]._flags & _VN_CONSTANT:
                sz = vn._size
                sa = int(ins[1]._loc.offset)
                if sz > 8:
                    if sa >= 64:
                        a = ALL
                    else:
                        a = (outc >> sa) ^ (ALL << (64 - sa))
                    bitsz = 8 * sz - sa
                    if bitsz < 64:
                        mask = ALL << bitsz
                        a = a & ~mask
                else:
                    a = outc >> sa if sa < 64 else 0
                b = ALL if outc != 0 else 0
                push(a, ins[0], worklist)
                push(b, ins[1], worklist)
            else:
                a = ALL if outc != 0 else 0
                push(a, ins[0], worklist)
                push(a, ins[1], worklist)
        elif opc == _OPC_INT_RIGHT:
            if ins[1]._flags & _VN_CONSTANT:
                sa = int(ins[1]._loc.offset)
                if sa >= 64:
                    a = 0
                else:
                    a = outc << sa
                b = ALL if outc != 0 else 0
                push(a, ins[0], worklist)
                push(b, ins[1], worklist)
            else:
                a = ALL if outc != 0 else 0
                push(a, ins[0], worklist)
                push(a, ins[1], worklist)
        elif opc in (_OPC_INT_LESS, _OPC_INT_LESSEE, _OPC_INT_EQ, _OPC_INT_NEQ):
            if outc == 0:
                a = 0
            else:
                a = ins[0].getNZMask() | ins[1].getNZMask()
            push(a, ins[0], worklist)
            push(a, ins[1], worklist)
        elif opc == _OPC_INSERT:
            ni = len(ins)
            if ni >= 4:
                imask = (1 << int(ins[3]._loc.offset)) - 1
                push(imask, ins[1], worklist)
                a = imask << int(ins[2]._loc.offset)
                push(outc & ~a, ins[0], worklist)
                b = ALL if outc != 0 else 0
                push(b, ins[2], worklist)
                push(b, ins[3], worklist)
            else:
                a = ALL if outc != 0 else 0
                for inv in ins:
                    push(a, inv, worklist)
        elif opc == _OPC_EXTRACT:
            ni = len(ins)
            if ni >= 3:
                emask = (1 << int(ins[2]._loc.offset)) - 1
                a = (emask & outc) << int(ins[1]._loc.offset)
                push(a, ins[0], worklist)
                b = ALL if outc != 0 else 0
                push(b, ins[1], worklist)
                push(b, ins[2], worklist)
            else:
                a = ALL if outc != 0 else 0
                for inv in ins:
                    push(a, inv, worklist)
        elif opc == _OPC_POPCOUNT or opc == _OPC_LZCOUNT:
            a = 16 * ins[0]._size - 1
            a &= outc
            b = ALL if a != 0 else 0
            push(b, ins[0], worklist)
        elif opc == _OPC_CALL or opc == _OPC_CALLIND:
            pass
        elif opc == _OPC_FLOAT_I2F:
            a = 0
            in0 = ins[0]
            if outc != 0:
                a = coveringmask(in0.getNZMask())
            push(a, in0, worklist)
        else:
            a = ALL if outc != 0 else 0
            for inv in ins:
                push(a, inv, worklist)

    # ------------------------------------------------------------------
    # neverConsumed  (C++ ActionDeadCode::neverConsumed)
    # ------------------------------------------------------------------
    @staticmethod
    def _neverConsumed(vn, data) -> bool:
        if vn.getSize() > 8:
            return False
        for desc in list(vn.getDescendants()):
            slot = desc.getSlot(vn)
            data.opSetInput(desc, data.newConstant(vn.getSize(), 0), slot)
        op = vn.getDef()
        if op.isCall():
            data.opUnsetOutput(op)
        else:
            data.opDestroy(op)
        return True

    # ------------------------------------------------------------------
    # gatherConsumedReturn  (C++ ActionDeadCode::gatherConsumedReturn)
    # ------------------------------------------------------------------
    @staticmethod
    def _gatherConsumedReturn(data) -> int:
        ALL = 0xFFFFFFFFFFFFFFFF
        proto = data.getFuncProto()
        if proto is not None:
            if proto.isOutputLocked():
                return ALL
        activeOut = data.getActiveOutput()
        if activeOut is not None:
            return ALL
        consumeVal = 0
        for op in data.beginOpAll():
            if op.code() != OpCode.CPUI_RETURN:
                continue
            if op.isDead():
                continue
            if op.numInput() > 1:
                vn = op.getIn(1)
                consumeVal |= minimalmask(vn.getNZMask())
        if proto is not None:
            val = proto.getReturnBytesConsumed()
            if val != 0:
                consumeVal &= calc_mask(val)
        return consumeVal

    # ------------------------------------------------------------------
    # markConsumedParameters  (C++ ActionDeadCode::markConsumedParameters)
    # ------------------------------------------------------------------
    @staticmethod
    def _markConsumedParameters(fc, worklist: List):
        ALL = 0xFFFFFFFFFFFFFFFF
        push = ActionDeadCode._pushConsumed
        callOp = fc.getOp()
        push(ALL, callOp.getIn(0), worklist)
        isLocked = fc.isInputLocked()
        isActive = fc.isInputActive()
        if isLocked or isActive:
            for i in range(1, callOp.numInput()):
                push(ALL, callOp.getIn(i), worklist)
            return
        for i in range(1, callOp.numInput()):
            vn = callOp.getIn(i)
            if vn.isAutoLive():
                consumeVal = ALL
            else:
                consumeVal = minimalmask(vn.getNZMask())
            bytesConsumed = fc.getInputBytesConsumed(i)
            if bytesConsumed != 0:
                consumeVal &= calc_mask(bytesConsumed)
            push(consumeVal, vn, worklist)

    # ------------------------------------------------------------------
    # lastChanceLoad  (C++ ActionDeadCode::lastChanceLoad)
    # ------------------------------------------------------------------
    @staticmethod
    def _lastChanceLoad(data, worklist: List) -> bool:
        ALL = 0xFFFFFFFFFFFFFFFF
        heritagePass = data.getHeritagePass()
        if heritagePass > 1:
            return False
        if data.isJumptableRecoveryOn():
            return False
        res = False
        for op in data.beginOpAll():
            if op.code() != OpCode.CPUI_LOAD:
                continue
            if op.isDead():
                continue
            vn = op.getOut()
            if vn is None:
                continue
            if vn.isConsumeVacuous():
                continue
            inv = op.getIn(1)
            if inv.isEventualConstant(3, 1):
                ActionDeadCode._pushConsumed(ALL, vn, worklist)
                vn.setAutoLiveHold()
                res = True
        return res

    # ------------------------------------------------------------------
    # apply  (C++ ActionDeadCode::apply)
    # ------------------------------------------------------------------
    def apply(self, data) -> int:
        worklist: List = []
        ALL = 0xFFFFFFFFFFFFFFFF
        push = self._pushConsumed
        manage = data.getArch()

        # Phase 1: Clear consume flags on all varnodes
        _cf = _CONSUME_FL; _af = _VN_ADDRFORCE; _dw = _VN_DIRECTWRITE
        for vn in list(data._vbank.beginLoc()):
            vn._addlflags &= ~_cf    # clearConsumeList + clearConsumeVacuous
            vn._consumed = 0         # setConsume(0)
            vn_flags = vn._flags
            if (vn_flags & _af) and not (vn_flags & _dw):
                vn._flags = vn_flags & ~_af  # clearAddrForce

        # Phase 2: Set pre-live registers — keep varnodes alive in spaces
        # that have deadcode analysis but haven't been heritaged yet.
        # C++ ref: coreaction.cc lines 3948-3959
        if manage is not None:
            for i in range(manage.numSpaces()):
                spc = manage.getSpace(i)
                if spc is None or not spc.doesDeadcode():
                    continue
                if data.deadRemovalAllowed(spc):
                    continue
                # Heritage not done yet for this space — mark ALL as consumed
                for vn in list(data._vbank.beginLoc()):
                    if vn._loc.base is spc:
                        push(ALL, vn, worklist)

        # Phase 3: Gather consumed return value
        returnConsume = self._gatherConsumedReturn(data)

        _OP_CALL    = 0x04  # PcodeOp.call
        _OP_SPEC    = 0x20000000  # PcodeOp.has_callspec
        _OP_INDSRC  = 0x400  # PcodeOp.indirect_source
        _OP_HOLD_OUTPUT = 0x80  # PcodeOp._addlflags: hold_output
        _VN_AUTOLIVE = 0x40100000  # Varnode.addrforce | Varnode.autolive_hold
        _OPC_RETURN = 10    # OpCode.CPUI_RETURN
        _OPC_BRIND  = 6     # OpCode.CPUI_BRANCHIND
        # Phase 4: Seed alive ops
        for op in list(data._obank.beginAlive()):
            op._flags &= ~_OP_INDSRC  # clearIndirectSource
            op_flags = op._flags
            ins = op._inrefs
            outvn = op._output
            if op_flags & _OP_CALL:  # op.isCall()
                if (op_flags & (_OP_CALL | _OP_SPEC)) == _OP_CALL:  # isCallWithoutSpec
                    for vn in ins:
                        push(ALL, vn, worklist)
                if outvn is None:  # not isAssignment
                    continue
                if op._addlflags & _OP_HOLD_OUTPUT:  # holdOutput
                    push(ALL, outvn, worklist)
            elif outvn is None:  # not isAssignment
                opc = op._opcode_enum
                if opc == _OPC_RETURN:
                    push(ALL, ins[0], worklist)
                    for i in range(1, len(ins)):
                        push(returnConsume, ins[i], worklist)
                elif opc == _OPC_BRIND:
                    jt = data.findJumpTable(op)
                    if jt is not None:
                        mask = jt.getSwitchVarConsume()
                    else:
                        mask = ALL
                    push(mask, ins[0], worklist)
                else:
                    for vn in ins:
                        push(ALL, vn, worklist)
                continue
            else:
                for vn in ins:
                    if vn is None or (vn._flags & _VN_AUTOLIVE):
                        push(ALL, vn, worklist)
            if outvn is not None and (outvn._flags & _VN_AUTOLIVE):
                push(ALL, outvn, worklist)

        # Phase 5: Mark consumed call parameters
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is not None:
                self._markConsumedParameters(fc, worklist)

        # Phase 6: Propagate consumed bits
        _pc = ActionDeadCode._propagateConsumed
        while worklist:
            _pc(worklist, push)

        # Phase 7: Last chance load — preserve volatile loads
        if self._lastChanceLoad(data, worklist):
            while worklist:
                _pc(worklist, push)

        # Phase 8: Remove dead varnodes/ops — per-space with doesDeadcode/deadRemovalAllowed
        if manage is not None and hasattr(manage, 'numSpaces'):
            for i in range(manage.numSpaces()):
                spc = manage.getSpace(i)
                if spc is None or not spc.doesDeadcode():
                    continue
                if not data.deadRemovalAllowed(spc):
                    continue
                changecount = 0
                _vacc = _VACCONSUME; _cf2 = _CONSUME_FL
                _op_call = 0x04
                for vn in list(data._vbank.beginLoc()):
                    if vn._loc.base is not spc:
                        continue
                    if not (vn._flags & _VN_WRITTEN):
                        continue
                    vn_addlfl = vn._addlflags
                    vacflag = vn_addlfl & _vacc
                    vn._addlflags = vn_addlfl & ~_cf2  # clearConsumeList + clearConsumeVacuous
                    if not vacflag:
                        op = vn._def
                        changecount += 1
                        if op._flags & _op_call:  # isCall
                            data.opUnsetOutput(op)
                        else:
                            data.opDestroy(op)
                    elif vn._consumed == 0:  # getConsume() == 0
                        if self._neverConsumed(vn, data):
                            changecount += 1
                if changecount != 0:
                    data.seenDeadcode(spc)
        else:
            # Fallback: no architecture — remove from all spaces (legacy behavior)
            _cf3 = _CONSUME_FL; _vacc2 = _VACCONSUME; _wr = _VN_WRITTEN; _oc = 0x04
            for vn in list(data._vbank.beginLoc()):
                if not (vn._flags & _wr):  # isWritten
                    continue
                vn_afl = vn._addlflags
                vacflag = vn_afl & _vacc2
                vn._addlflags = vn_afl & ~_cf3  # clearConsumeList + clearConsumeVacuous
                if not vacflag:
                    op = vn._def
                    if op._flags & _oc:  # isCall
                        data.opUnsetOutput(op)
                    else:
                        data.opDestroy(op)
                elif vn.getConsume() == 0:
                    self._neverConsumed(vn, data)

        data.clearDeadVarnodes()
        data.clearDeadOps()
        return 0
