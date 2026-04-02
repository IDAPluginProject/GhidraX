"""
Corresponds to: coreaction.hh / coreaction.cc (part 2)
Remaining Action stubs + universalAction pipeline wiring.
"""
from __future__ import annotations
from typing import TYPE_CHECKING
from ghidra.transform.action import (
    Action, ActionGroup, ActionRestartGroup, ActionPool, ActionDatabase,
)
from ghidra.transform.coreaction import *

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# --- Prototype / parameter Actions ---

class ActionNormalizeSetup(Action):
    """Clear prototype locks for re-evaluation during normalization."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "normalizesetup", g)
    def clone(self, gl):
        return ActionNormalizeSetup(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        fp = data.getFuncProto()
        if hasattr(fp, 'clearInput'):
            fp.clearInput()
        return 0

class ActionPrototypeTypes(Action):
    """Apply prototype types: strip indirect registers from RETURN, force locked inputs.

    C++ ref: ``ActionPrototypeTypes::apply``
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "prototypetypes", g)
    def clone(self, gl):
        return ActionPrototypeTypes(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        # Set the evaluation prototype if we are not already locked
        glb = data.getArch() if hasattr(data, 'getArch') else None
        if glb is not None:
            evalfp = getattr(glb, 'evalfp_current', None)
            if evalfp is None:
                evalfp = getattr(glb, 'defaultfp', None)
            proto = data.getFuncProto()
            if evalfp is not None and not proto.isModelLocked():
                if not hasattr(proto, 'hasMatchingModel') or not proto.hasMatchingModel(evalfp):
                    proto.setModel(evalfp)
        # Strip the indirect register from all RETURN ops
        for op in list(data._obank.beginAlive()):
            if op.code() != OpCode.CPUI_RETURN:
                continue
            if op.isDead():
                continue
            if op.numInput() > 0 and not op.getIn(0).isConstant():
                vn = data.newConstant(op.getIn(0).getSize(), 0)
                data.opSetInput(op, vn, 0)
        # Handle return value: output-locked path or active output recovery
        proto = data.getFuncProto()
        if proto.isOutputLocked():
            outparam = proto.getOutput()
            if outparam is not None and hasattr(outparam, 'getType'):
                tp = outparam.getType()
                if tp is not None and hasattr(tp, 'getMetatype') and tp.getMetatype() != 15:  # TYPE_VOID=15
                    for op in list(data._obank.beginAlive()):
                        if op.code() != OpCode.CPUI_RETURN or op.isDead():
                            continue
                        if hasattr(op, 'getHaltType') and op.getHaltType() != 0:
                            continue
                        if op.numInput() > 1:
                            continue  # Return register already wired (e.g. from prior restart cycle)
                        vn = data.newVarnode(outparam.getSize(), outparam.getAddress())
                        data.opInsertInput(op, vn, op.numInput())
                        if hasattr(vn, 'updateType'):
                            vn.updateType(tp, True, True)
        else:
            data.initActiveOutput()
        # Force locked inputs to exist as varnodes
        if proto.isInputLocked():
            graph = data.getBasicBlocks()
            if graph.getSize() > 0:
                for i in range(proto.numParams()):
                    param = proto.getParam(i)
                    if param is None:
                        continue
                    vn = data.newVarnode(param.getSize(), param.getAddress())
                    data.setInputVarnode(vn)
        return 0

class ActionDefaultParams(Action):
    """Set up default parameter information for calls without locked prototypes.

    C++ ref: ``ActionDefaultParams::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "defaultparams", g)
    def clone(self, gl):
        return ActionDefaultParams(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        arch = data.getArch()
        evalfp = getattr(arch, 'evalfp_called', None)
        if evalfp is None:
            evalfp = getattr(arch, 'defaultfp', None)
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if not fc.hasModel():
                otherfunc = fc.getFuncdata() if hasattr(fc, 'getFuncdata') else None
                if otherfunc is not None:
                    if hasattr(fc, 'copy'):
                        fc.copy(otherfunc.getFuncProto())
                    if not fc.isModelLocked():
                        if evalfp is not None and hasattr(fc, 'hasMatchingModel'):
                            if not fc.hasMatchingModel(evalfp):
                                fc.setModel(evalfp)
                else:
                    if evalfp is not None and hasattr(fc, 'setInternal'):
                        voidtype = arch.types.getTypeVoid() if hasattr(arch, 'types') else None
                        if voidtype is not None:
                            fc.setInternal(evalfp, voidtype)
            if hasattr(fc, 'insertPcode'):
                fc.insertPcode(data)
        return 0

class ActionExtraPopSetup(Action):
    """Set up INDIRECT or INT_ADD ops to model stack-pointer changes across calls."""
    def __init__(self, g, ss=None):
        super().__init__(Action.rule_onceperfunc, "extrapopsetup", g)
        self._stackspace = ss
    def clone(self, gl):
        return ActionExtraPopSetup(self._basegroup, self._stackspace) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import Address
        if self._stackspace is None:
            return 0
        if not hasattr(self._stackspace, 'getSpacebase'):
            return 0
        point = self._stackspace.getSpacebase(0)
        sb_addr = Address(point.space, point.offset)
        sb_size = point.size
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            extrapop = fc.getExtraPop()
            if extrapop == 0:
                continue
            op = data.newOp(2, fc.getOp().getAddr())
            data.newVarnodeOut(sb_size, sb_addr, op)
            data.opSetInput(op, data.newVarnode(sb_size, sb_addr), 0)
            if extrapop != 0x8000:  # Not ProtoModel.extrapop_unknown
                fc.setEffectiveExtraPop(extrapop)
                data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
                data.opSetInput(op, data.newConstant(sb_size, extrapop), 1)
                data.opInsertAfter(op, fc.getOp())
            else:
                data.opSetOpcode(op, OpCode.CPUI_INDIRECT)
                data.opSetInput(op, data.newVarnodeIop(fc.getOp()), 1)
                data.opInsertBefore(op, fc.getOp())
        return 0

class ActionFuncLink(Action):
    """Link call sites to function prototypes, setting up inputs/outputs."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "funclink", g)
    def clone(self, gl):
        return ActionFuncLink(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            self._funcLinkInput(fc, data)
            self._funcLinkOutput(fc, data)
        return 0

    @staticmethod
    def _funcLinkInput(fc, data):
        """Set up input parameters for a call based on prototype.

        C++ ref: ``ActionFuncLink::funcLinkInput`` in coreaction.cc
        For unlocked prototypes, initializes active input and creates a
        stack placeholder (INT_ADD + LOAD) so heritage can track the
        stack pointer through calls.
        """
        inputlocked = fc.isInputLocked()
        spacebase = fc.getSpacebase() if hasattr(fc, 'getSpacebase') else None

        if not inputlocked:
            if hasattr(fc, 'initActiveInput'):
                fc.initActiveInput()

        if inputlocked:
            op = fc.getOp()
            numparam = fc.numParams()
            for i in range(numparam):
                param = fc.getParam(i)
                if param is None:
                    continue
                data.opInsertInput(op, data.newVarnode(param.getSize(), param.getAddress()), op.numInput())

        if spacebase is not None:
            fc.createPlaceholder(data, spacebase)

    @staticmethod
    def _funcLinkOutput(fc, data):
        """Set up output for a call based on prototype."""
        callop = fc.getOp()
        if callop.getOut() is not None:
            data.opUnsetOutput(callop)
        if not fc.isOutputLocked():
            if hasattr(fc, 'initActiveOutput'):
                fc.initActiveOutput()
            return
        outparam = fc.getOutput()
        if outparam is None:
            return
        from ghidra.types.datatype import TYPE_VOID
        outtype = outparam.getType()
        if outtype is not None and outtype.getMetatype() != TYPE_VOID:
            data.newVarnodeOut(outparam.getSize(), outparam.getAddress(), callop)

class ActionFuncLinkOutOnly(Action):
    """Link only output prototypes for calls (used during noproto phase)."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "funclinkoutonly", g)
    def clone(self, gl):
        return ActionFuncLinkOutOnly(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            ActionFuncLink._funcLinkOutput(data.getCallSpecs(i), data)
        return 0

class ActionParamDouble(Action):
    """Split double-precision parameters into their component pieces at call sites.

    C++ ref: ``ActionParamDouble::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "paramdouble", g)
    def clone(self, gl):
        return ActionParamDouble(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.core.space import IPTR_SPACEBASE
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            op = fc.getOp()
            if fc.isInputActive():
                active = fc.getActiveInput()
                if active is None:
                    continue
                j = 0
                while j < active.getNumTrials():
                    trial = active.getTrial(j)
                    if trial.isChecked() or trial.isUnref():
                        j += 1
                        continue
                    spc = trial.getAddress().getSpace()
                    if spc.getType() != IPTR_SPACEBASE:
                        j += 1
                        continue
                    slot = trial.getSlot()
                    if slot >= op.numInput():
                        j += 1
                        continue
                    vn = op.getIn(slot)
                    if not vn.isWritten():
                        j += 1
                        continue
                    concatop = vn.getDef()
                    if concatop.code() != OpCode.CPUI_PIECE:
                        j += 1
                        continue
                    if not fc.hasModel():
                        j += 1
                        continue
                    mostvn = concatop.getIn(0)
                    leastvn = concatop.getIn(1)
                    splitsize = mostvn.getSize() if spc.isBigEndian() else leastvn.getSize()
                    if hasattr(fc, 'checkInputSplit') and fc.checkInputSplit(trial.getAddress(), trial.getSize(), splitsize):
                        active.splitTrial(j, splitsize)
                        if spc.isBigEndian():
                            data.opInsertInput(op, mostvn, slot)
                            data.opSetInput(op, leastvn, slot + 1)
                        else:
                            data.opInsertInput(op, leastvn, slot)
                            data.opSetInput(op, mostvn, slot + 1)
                        self._count += 1
                        # Don't increment j - check nested CONCATs
                    else:
                        j += 1
            elif not fc.isInputLocked() and (hasattr(data, 'isDoublePrecisOn') and data.isDoublePrecisOn()):
                # Search for double precision objects that might become params
                maxslot = op.numInput() - 1
                j = 1
                while j < maxslot:
                    vn1 = op.getIn(j)
                    vn2 = op.getIn(j + 1)
                    # Would check SplitVarnode.inHandHi/inHandLo for adjacent slots
                    j += 1
        return 0

class ActionActiveParam(Action):
    """Actively recover function parameters through trial analysis.

    C++ ref: ``ActionActiveParam::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "activeparam", g)
    def clone(self, gl):
        return ActionActiveParam(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.database.varmap import AliasChecker

        aliascheck = AliasChecker()
        stackspace = data.getArch().getStackSpace() if hasattr(data, 'getArch') and data.getArch() is not None and hasattr(data.getArch(), 'getStackSpace') else None
        aliascheck.gather(data, stackspace, True)
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            try:
                if not fc.isInputActive():
                    continue
                activeinput = fc.getActiveInput()
                if activeinput is None:
                    continue
                trimmable = (activeinput.getNumPasses() > 0) or (fc.getOp().code() != OpCode.CPUI_CALLIND)
                if not activeinput.isFullyChecked():
                    if hasattr(fc, 'checkInputTrialUse'):
                        fc.checkInputTrialUse(data, aliascheck)
                activeinput.finishPass()
                if activeinput.getNumPasses() > activeinput.getMaxPass():
                    activeinput.markFullyChecked()
                else:
                    self._count += 1
                if trimmable and activeinput.isFullyChecked():
                    if hasattr(activeinput, 'needsFinalCheck') and activeinput.needsFinalCheck():
                        if hasattr(fc, 'finalInputCheck'):
                            fc.finalInputCheck()
                    if hasattr(fc, 'resolveModel'):
                        fc.resolveModel(activeinput)
                    if hasattr(fc, 'deriveInputMap'):
                        fc.deriveInputMap(activeinput)
                    if hasattr(fc, 'buildInputFromTrials'):
                        fc.buildInputFromTrials(data)
                    fc.clearActiveInput()
                    self._count += 1
            except Exception as err:
                op = fc.getOp()
                msg = f"Error processing {fc.getName()}"
                if op is not None:
                    msg += f" called at {op.getSeqNum()}"
                msg += f": {err}"
                raise RuntimeError(msg) from err
        return 0

class ActionReturnRecovery(Action):
    """Recover return values through ancestor analysis of RETURN ops."""
    def __init__(self, g): super().__init__(0, "returnrecovery", g)
    def clone(self, gl):
        return ActionReturnRecovery(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def buildReturnOutput(active, retop, data) -> None:
        from ghidra.core.opcodes import OpCode

        newparam = [retop.getIn(0)]
        for i in range(active.getNumTrials()):
            curtrial = active.getTrial(i)
            if not curtrial.isUsed():
                break
            if curtrial.getSlot() >= retop.numInput():
                break
            newparam.append(retop.getIn(curtrial.getSlot()))

        if len(newparam) <= 2:
            data.opSetAllInput(retop, newparam)
            return

        if len(newparam) == 3:
            lovn = newparam[1]
            hivn = newparam[2]
            triallo = active.getTrial(0)
            trialhi = active.getTrial(1)
            arch = data.getArch() if hasattr(data, "getArch") else None
            joinaddr = None
            if arch is not None and hasattr(arch, "constructJoinAddress"):
                joinaddr = arch.constructJoinAddress(
                    arch.translate,
                    trialhi.getAddress(),
                    trialhi.getSize(),
                    triallo.getAddress(),
                    triallo.getSize(),
                )
            newop = data.newOp(2, retop.getAddr())
            data.opSetOpcode(newop, OpCode.CPUI_PIECE)
            if joinaddr is not None:
                newwhole = data.newVarnodeOut(trialhi.getSize() + triallo.getSize(), joinaddr, newop)
            else:
                newwhole = data.newUniqueOut(trialhi.getSize() + triallo.getSize(), newop)
            newwhole.setWriteMask()
            data.opInsertBefore(newop, retop)
            newparam.pop()
            newparam[-1] = newwhole
            data.opSetAllInput(retop, newparam)
            data.opSetInput(newop, hivn, 0)
            data.opSetInput(newop, lovn, 1)
            return

        newparam = [retop.getIn(0)]
        offmatch = 0
        preexist = None
        for i in range(active.getNumTrials()):
            curtrial = active.getTrial(i)
            if not curtrial.isUsed():
                break
            if curtrial.getSlot() >= retop.numInput():
                break
            if preexist is None:
                preexist = retop.getIn(curtrial.getSlot())
                offmatch = curtrial.getOffset() + curtrial.getSize()
            elif offmatch == curtrial.getOffset():
                offmatch += curtrial.getSize()
                vn = retop.getIn(curtrial.getSlot())
                newop = data.newOp(2, retop.getAddr())
                data.opSetOpcode(newop, OpCode.CPUI_PIECE)
                addr = preexist.getAddr()
                if vn.getAddr() < addr:
                    addr = vn.getAddr()
                newout = data.newVarnodeOut(preexist.getSize() + vn.getSize(), addr, newop)
                newout.setWriteMask()
                data.opSetInput(newop, vn, 0)
                data.opSetInput(newop, preexist, 1)
                data.opInsertBefore(newop, retop)
                preexist = newout
            else:
                break
        if preexist is not None:
            newparam.append(preexist)
        data.opSetAllInput(retop, newparam)

    def apply(self, data):
        active = data.getActiveOutput()
        if active is None:
            return 0
        from ghidra.analysis.ancestor import AncestorRealistic
        from ghidra.core.opcodes import OpCode

        maxancestor = data.getArch().trim_recurse_max if hasattr(data, 'getArch') and data.getArch() is not None else 0
        ancestorReal = AncestorRealistic()
        for op in list(data.beginOp(OpCode.CPUI_RETURN)):
            if op.isDead():
                continue
            if op.getHaltType() != 0:
                continue
            for i in range(active.getNumTrials()):
                trial = active.getTrial(i)
                if trial.isChecked():
                    continue
                slot = trial.getSlot()
                if slot >= op.numInput():
                    continue
                vn = op.getIn(slot)
                if ancestorReal.execute(op, slot, trial, False):
                    if data.ancestorOpUse(maxancestor, vn, op, trial, 0, 0):
                        trial.markActive()
                self._count += 1
        active.finishPass()
        if active.getNumPasses() > active.getMaxPass():
            active.markFullyChecked()
        if active.isFullyChecked():
            proto = data.getFuncProto() if hasattr(data, 'getFuncProto') else None
            if proto is not None and hasattr(proto, 'deriveOutputMap'):
                proto.deriveOutputMap(active)
            for op in list(data.beginOp(OpCode.CPUI_RETURN)):
                if op.isDead():
                    continue
                if op.getHaltType() != 0:
                    continue
                ActionReturnRecovery.buildReturnOutput(active, op, data)
            data.clearActiveOutput()
            self._count += 1
        return 0

class ActionRestrictLocal(Action):
    """Restrict local variable ranges based on call effects.

    C++ ref: ``ActionRestrictLocal::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "restrictlocal", g)
    def clone(self, gl):
        return ActionRestrictLocal(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.core.space import IPTR_SPACEBASE
        from ghidra.fspec.fspec import EffectRecord
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        # Mark spacebase parameters of locked calls as not mapped
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if not fc.isInputLocked():
                continue
            spoff = fc.getSpacebaseOffset() if hasattr(fc, 'getSpacebaseOffset') else None
            if spoff is None:
                continue
            numparam = fc.numParams()
            for j in range(numparam):
                param = fc.getParam(j)
                if param is None:
                    continue
                addr = param.getAddress()
                if addr.getSpace() is None:
                    continue
                if addr.getSpace().getType() != IPTR_SPACEBASE:
                    continue
                off = (spoff + addr.getOffset()) & ((1 << (addr.getSpace().getAddrSize() * 8)) - 1)
                if localmap is not None and hasattr(localmap, 'markNotMapped'):
                    localmap.markNotMapped(addr.getSpace(), off, param.getSize(), True)

        # Mark storage for saved registers/return-address slots as not mapped.
        proto = data.getFuncProto()
        if localmap is not None and hasattr(proto, 'effectBegin'):
            for eff in proto.effectBegin():
                if hasattr(eff, 'getType') and eff.getType() == EffectRecord.killedbycall:
                    continue
                vn = data.findVarnodeInput(eff.getSize(), eff.getAddress()) if hasattr(data, 'findVarnodeInput') else None
                if vn is not None and vn.isUnaffected():
                    for op in vn.getDescendants():
                        if op.code() != OpCode.CPUI_COPY:
                            continue
                        outvn = op.getOut()
                        if outvn is None:
                            continue
                        if hasattr(localmap, 'isUnaffectedStorage') and not localmap.isUnaffectedStorage(outvn):
                            continue
                        if hasattr(localmap, 'markNotMapped'):
                            localmap.markNotMapped(outvn.getSpace(), outvn.getOffset(), outvn.getSize(), False)
            # Return-address effects are tracked on the saved INDIRECT output, but the
            # corresponding effect input is not always materialized at the translated
            # stack offset. Mark the saved storage directly so the later restructure pass
            # can clear mapped/addrforce exactly like the native pipeline.
            for vn in list(data._vbank.beginLoc()):
                if not vn.isWritten() or not (hasattr(vn, 'isReturnAddress') and vn.isReturnAddress()):
                    continue
                defop = vn.getDef()
                if defop is None or defop.code() != OpCode.CPUI_INDIRECT:
                    continue
                if hasattr(localmap, 'isUnaffectedStorage') and not localmap.isUnaffectedStorage(vn):
                    continue
                if hasattr(localmap, 'markNotMapped'):
                    localmap.markNotMapped(vn.getSpace(), vn.getOffset(), vn.getSize(), False)
        return 0

class ActionDynamicMapping(Action):
    """Map dynamic variables to their storage locations using DynamicHash."""
    def __init__(self, g): super().__init__(0, "dynamicmapping", g)
    def clone(self, gl):
        return ActionDynamicMapping(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        localmap = data.getLocalScope()
        if localmap is None:
            return 0
        if not hasattr(localmap, 'beginDynamic'):
            return 0
        from ghidra.analysis.dynamic import DynamicHash
        dhash = DynamicHash()
        for entry in localmap.beginDynamic():
            if hasattr(data, 'attemptDynamicMapping'):
                if data.attemptDynamicMapping(entry, dhash):
                    self._count += 1
        return 0

class ActionRestructureVarnode(Action):
    """Restructure Varnodes based on local variable recovery and symbol mapping.

    C++ ref: ``ActionRestructureVarnode::apply`` in coreaction.cc
    """
    def __init__(self, g):
        super().__init__(0, "restructure_varnode", g)
        self._numpass: int = 0
    def clone(self, gl):
        return ActionRestructureVarnode(self._basegroup) if gl.contains(self._basegroup) else None
    def reset(self, data):
        super().reset(data)
        self._numpass = 0
    def apply(self, data):
        l1 = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if l1 is None:
            return 0
        aliasyes = (self._numpass != 0)
        try:
            if hasattr(l1, 'restructureVarnode'):
                l1.restructureVarnode(aliasyes)
        except (AttributeError, RuntimeError, TypeError):
            pass  # Infrastructure not fully ported yet
        try:
            if hasattr(data, 'syncVarnodesWithSymbols'):
                if data.syncVarnodesWithSymbols(l1, False, aliasyes):
                    self._count += 1
        except (AttributeError, RuntimeError, TypeError):
            pass
        if hasattr(data, 'isJumptableRecoveryOn') and data.isJumptableRecoveryOn():
            if hasattr(self, '_protectSwitchPaths'):
                self._protectSwitchPaths(data)
        self._numpass += 1
        return 0

class ActionLikelyTrash(Action):
    """Detect input varnodes that are likely trash (unused register values).

    C++ ref: ``ActionLikelyTrash`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "likelytrash", g)
    def clone(self, gl):
        return ActionLikelyTrash(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def countMarks(op) -> int:
        """Count number of inputs to op which have their mark set."""
        from ghidra.core.opcodes import OpCode
        res = 0
        for i in range(op.numInput()):
            vn = op.getIn(i)
            while True:
                if vn.isMark():
                    res += 1
                    break
                if not vn.isWritten():
                    break
                defOp = vn.getDef()
                if defOp is op:  # Looped all the way around
                    res += 1
                    break
                if defOp.code() != OpCode.CPUI_INDIRECT:
                    break
                vn = defOp.getIn(0)
        return res

    @staticmethod
    def traceTrash(vn, indlist: list) -> bool:
        """Decide if the given Varnode only ever flows into INDIRECT.

        C++ ref: ``ActionLikelyTrash::traceTrash``
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import calc_mask
        allroutes = []  # merging ops with > 1 input
        markedlist = []
        vn.setMark()
        markedlist.append(vn)
        istrash = True
        traced = 0

        while traced < len(markedlist):
            curvn = markedlist[traced]
            traced += 1
            for op in curvn.getDescendants():
                outvn = op.getOut()
                opc = op.code()
                if opc == OpCode.CPUI_INDIRECT:
                    if outvn is not None and outvn.isPersist():
                        istrash = False
                    elif op.isIndirectStore():
                        if outvn is not None and not outvn.isMark():
                            outvn.setMark()
                            markedlist.append(outvn)
                    else:
                        indlist.append(op)
                elif opc == OpCode.CPUI_SUBPIECE:
                    if outvn is not None and outvn.isPersist():
                        istrash = False
                    elif outvn is not None and not outvn.isMark():
                        outvn.setMark()
                        markedlist.append(outvn)
                elif opc in (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_PIECE):
                    if outvn is not None and outvn.isPersist():
                        istrash = False
                    else:
                        if not op.isMark():
                            op.setMark()
                            allroutes.append(op)
                        nummark = ActionLikelyTrash.countMarks(op)
                        if nummark == op.numInput():
                            if outvn is not None and not outvn.isMark():
                                outvn.setMark()
                                markedlist.append(outvn)
                elif opc == OpCode.CPUI_INT_AND:
                    if op.getIn(1).isConstant():
                        val = op.getIn(1).getOffset()
                        mask = calc_mask(op.getIn(1).getSize())
                        if val in ((mask << 8) & mask, (mask << 16) & mask, (mask << 32) & mask):
                            indlist.append(op)
                            continue
                    istrash = False
                else:
                    istrash = False
                if not istrash:
                    break
            if not istrash:
                break

        for op in allroutes:
            if op.getOut() is not None and not op.getOut().isMark():
                istrash = False
            op.clearMark()
        for v in markedlist:
            v.clearMark()
        return istrash

    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        indlist = []
        proto = data.getFuncProto()
        if not hasattr(proto, 'trashBegin'):
            return 0
        for vdata in proto.trashBegin():
            vn = data.findCoveredInput(vdata.size, vdata.getAddr()) if hasattr(data, 'findCoveredInput') else None
            if vn is None:
                continue
            if vn.isTypeLock() or vn.isNameLock():
                continue
            indlist.clear()
            if not ActionLikelyTrash.traceTrash(vn, indlist):
                continue
            for op in indlist:
                if op.code() == OpCode.CPUI_INDIRECT:
                    data.opSetInput(op, data.newConstant(op.getOut().getSize(), 0), 0)
                    if hasattr(data, 'markIndirectCreation'):
                        data.markIndirectCreation(op, False)
                elif op.code() == OpCode.CPUI_INT_AND:
                    data.opSetInput(op, data.newConstant(op.getIn(1).getSize(), 0), 1)
                self._count += 1
        return 0

class ActionSwitchNorm(Action):
    """Normalize switch/case statements by recovering labels.

    C++ ref: ``ActionSwitchNorm::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "switchnorm", g)
    def clone(self, gl):
        return ActionSwitchNorm(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        numjt = data.numJumpTables() if hasattr(data, 'numJumpTables') else 0
        for i in range(numjt):
            jt = data.getJumpTable(i)
            if jt is None:
                continue
            if not (hasattr(jt, 'isLabelled') and jt.isLabelled()):
                if hasattr(jt, 'matchModel'):
                    jt.matchModel(data)
                if hasattr(jt, 'recoverLabels'):
                    jt.recoverLabels(data)
                if hasattr(jt, 'foldInNormalization'):
                    jt.foldInNormalization(data)
                self._count += 1
            if hasattr(jt, 'foldInGuards') and jt.foldInGuards(data):
                graph = data.getStructure() if hasattr(data, 'getStructure') else None
                if graph is not None and hasattr(graph, 'clear'):
                    graph.clear()
                self._count += 1
        return 0

class ActionUnjustifiedParams(Action):
    """Check for input varnodes that don't match the prototype and extend them.

    C++ ref: ``ActionUnjustifiedParams::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "unjustparams", g)
    def clone(self, gl):
        return ActionUnjustifiedParams(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.pcoderaw import VarnodeData
        from ghidra.core.address import Address
        proto = data.getFuncProto()
        if not hasattr(proto, 'unjustifiedInputParam'):
            return 0
        inputs = [vn for vn in data._vbank.beginDef() if vn.isInput()]
        idx = 0
        while idx < len(inputs):
            vn = inputs[idx]
            idx += 1
            vdata = VarnodeData()
            if not proto.unjustifiedInputParam(vn.getAddr(), vn.getSize(), vdata):
                continue
            # Check for overlapping inputs that extend the container
            newcontainer = True
            while newcontainer:
                newcontainer = False
                overlaps = False
                for prev_vn in inputs[:idx]:
                    if prev_vn.getSpace() is not vdata.space:
                        continue
                    last_off = prev_vn.getOffset() + prev_vn.getSize() - 1
                    if last_off >= vdata.offset and prev_vn.getOffset() < vdata.offset:
                        overlaps = True
                        endpoint = vdata.offset + vdata.size
                        vdata.offset = prev_vn.getOffset()
                        vdata.size = endpoint - vdata.offset
                if not overlaps:
                    break
                newcontainer = proto.unjustifiedInputParam(
                    Address(vdata.space, vdata.offset), vdata.size, vdata)
            if hasattr(data, 'adjustInputVarnodes'):
                data.adjustInputVarnodes(Address(vdata.space, vdata.offset), vdata.size)
            # Reset iterator because of additions and deletions
            inputs = [v for v in data._vbank.beginDef() if v.isInput()]
            idx = 0
            self._count += 1
        return 0

class ActionActiveReturn(Action):
    """Check active return value recovery for each call site.

    C++ ref: ``ActionActiveReturn::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "activereturn", g)
    def clone(self, gl):
        return ActionActiveReturn(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if not (hasattr(fc, 'isOutputActive') and fc.isOutputActive()):
                continue
            activeoutput = fc.getActiveOutput() if hasattr(fc, 'getActiveOutput') else None
            if activeoutput is None:
                continue
            trialvn = []
            if hasattr(fc, 'checkOutputTrialUse'):
                fc.checkOutputTrialUse(data, trialvn)
            if hasattr(fc, 'deriveOutputMap'):
                fc.deriveOutputMap(activeoutput)
            if hasattr(fc, 'buildOutputFromTrials'):
                fc.buildOutputFromTrials(data, trialvn)
            if hasattr(fc, 'clearActiveOutput'):
                fc.clearActiveOutput()
            self._count += 1
        return 0

class ActionReturnSplit(Action):
    """Split RETURN blocks that have goto edges, so each goto gets its own copy.

    C++ ref: ``ActionReturnSplit::apply`` in blockaction.cc
    """
    def __init__(self, g): super().__init__(0, "returnsplit", g)
    def clone(self, gl):
        return ActionReturnSplit(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def gatherReturnGotos(parent, vec) -> None:
        """Gather all blocks that have goto edge to a RETURN.

        C++ ref: ``ActionReturnSplit::gatherReturnGotos`` in blockaction.cc
        """
        from ghidra.block.block import FlowBlock
        for i in range(parent.sizeIn()):
            bl = parent.getIn(i)
            if hasattr(bl, 'getCopyMap'):
                bl = bl.getCopyMap()
            while bl is not None:
                if not bl.isMark():
                    ret = None
                    if bl.getType() == FlowBlock.t_goto:
                        if bl.gotoPrints():
                            ret = bl.getGotoTarget()
                    elif bl.getType() == FlowBlock.t_if:
                        ret = bl.getGotoTarget()
                    if ret is not None:
                        while ret.getType() != FlowBlock.t_basic:
                            ret = ret.subBlock(0)
                        if ret is parent:
                            bl.setMark()
                            vec.append(bl)
                bl = bl.getParent()

    @staticmethod
    def isSplittable(b) -> bool:
        """Check if a RETURN block is simple enough to split.

        C++ ref: ``ActionReturnSplit::isSplittable`` in blockaction.cc
        """
        from ghidra.core.opcodes import OpCode
        for op in b.beginOp():
            opc = op.code()
            if opc == OpCode.CPUI_MULTIEQUAL:
                continue
            if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_RETURN:
                for i in range(op.numInput()):
                    inp = op.getIn(i)
                    if inp.isConstant():
                        continue
                    if inp.isAnnotation():
                        continue
                    if inp.isFree():
                        return False
                continue
            return False
        return True

    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getStructure() if hasattr(data, 'getStructure') else None
        if graph is None or graph.getSize() == 0:
            return 0
        splitedge = []
        retnode = []
        for op in list(data.beginOp(OpCode.CPUI_RETURN)):
            if op.isDead():
                continue
            parent = op.getParent()
            if parent.sizeIn() <= 1:
                continue
            if not ActionReturnSplit.isSplittable(parent):
                continue
            gotoblocks = []
            ActionReturnSplit.gatherReturnGotos(parent, gotoblocks)
            if not gotoblocks:
                continue
            splitcount = 0
            for i in range(parent.sizeIn() - 1, -1, -1):
                bl = parent.getIn(i)
                if hasattr(bl, 'getCopyMap'):
                    bl = bl.getCopyMap()
                while bl is not None:
                    if hasattr(bl, 'isMark') and bl.isMark():
                        splitedge.append(i)
                        retnode.append(parent)
                        bl = None
                        splitcount += 1
                    else:
                        bl = bl.getParent() if hasattr(bl, 'getParent') else None
            for gb in gotoblocks:
                gb.clearMark()
            if parent.sizeIn() == splitcount and splitedge:
                splitedge.pop()
                retnode.pop()
        for i in range(len(splitedge)):
            if retnode[i].sizeIn() <= 1:
                continue
            if hasattr(data, 'nodeSplit'):
                data.nodeSplit(retnode[i], splitedge[i])
            self._count += 1
        return 0

# --- Merge / output Actions ---

class ActionAssignHigh(Action):
    """Assign initial HighVariable objects to each Varnode."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "assignhigh", g)
    def clone(self, gl):
        return ActionAssignHigh(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        data.setHighLevel()
        return 0

class ActionMergeRequired(Action):
    """Make required Varnode merges as dictated by MULTIEQUAL, INDIRECT, and addrtied.

    C++ ref: ``ActionMergeRequired::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergerequired", g)
    def clone(self, gl):
        return ActionMergeRequired(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None:
            if hasattr(merge, 'mergeAddrTied'):
                merge.mergeAddrTied()
            if hasattr(merge, 'groupPartials'):
                merge.groupPartials()
            if hasattr(merge, 'mergeMarker'):
                merge.mergeMarker()
        return 0

class ActionMergeAdjacent(Action):
    """Try to merge op's input Varnode to its output if they are at the same storage location.

    C++ ref: ``ActionMergeAdjacent::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergeadjacent", g)
    def clone(self, gl):
        return ActionMergeAdjacent(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'mergeAdjacent'):
            merge.mergeAdjacent()
        return 0

class ActionMergeCopy(Action):
    """Try to merge the input and output Varnodes of a CPUI_COPY op.

    C++ ref: ``ActionMergeCopy::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergecopy", g)
    def clone(self, gl):
        return ActionMergeCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'mergeOpcode'):
            merge.mergeOpcode(OpCode.CPUI_COPY)
        return 0

class ActionMergeMultiEntry(Action):
    """Try to merge Varnodes specified by Symbols with multiple SymbolEntrys.

    C++ ref: ``ActionMergeMultiEntry::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergemultientry", g)
    def clone(self, gl):
        return ActionMergeMultiEntry(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'mergeMultiEntry'):
            merge.mergeMultiEntry()
        return 0

class ActionMergeType(Action):
    """Try to merge Varnodes of the same type (if they don't hold different values at the same time).

    C++ ref: ``ActionMergeType::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mergetype", g)
    def clone(self, gl):
        return ActionMergeType(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'mergeByDatatype'):
            merge.mergeByDatatype(list(data.beginLoc()))
        return 0

class ActionMarkExplicit(Action):
    """Mark Varnodes that should be printed as explicit variables.

    C++ ref: ``ActionMarkExplicit::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markexplicit", g)
    def clone(self, gl):
        return ActionMarkExplicit(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def baseExplicit(vn, maxref: int) -> int:
        """Determine if a Varnode should be marked explicit.

        Returns -1 or -2 if explicit, otherwise the descendant count.
        C++ ref: ``ActionMarkExplicit::baseExplicit``
        """
        defop = vn.getDef()
        if defop is None:
            return -1
        if defop.isMarker():
            return -1
        # Workaround: INDIRECT/MULTIEQUAL are markers in C++ but may lack
        # the marker flag in Python (setting it globally breaks merge phase).
        from ghidra.core.opcodes import OpCode as _OC
        if defop.code() in (_OC.CPUI_INDIRECT, _OC.CPUI_MULTIEQUAL):
            return -1
        if defop.isCall():
            from ghidra.core.opcodes import OpCode
            if defop.code() == OpCode.CPUI_NEW and defop.numInput() == 1:
                return -2  # Explicit, but may need special printing
            return -1
        high = vn.getHigh()
        if high is not None and hasattr(high, 'numInstances') and high.numInstances() > 1:
            return -1  # Must not be merged at all
        if vn.isAddrTied():
            from ghidra.core.opcodes import OpCode
            if defop.code() == OpCode.CPUI_SUBPIECE:
                vin = defop.getIn(0)
                if vin.isAddrTied():
                    return -1
            useOp = vn.loneDescend()
            if useOp is None:
                return -1
            if useOp.code() == OpCode.CPUI_INT_ZEXT:
                vnout = useOp.getOut()
                if vnout is None or not vnout.isAddrTied():
                    return -1
            elif useOp.code() == OpCode.CPUI_PIECE:
                # C++ uses PieceNode::findRoot to check if vn is root of PIECE tree
                rootVn = vn
                if hasattr(vn, 'loneDescend'):
                    # Walk up PIECE chain to find root
                    cur = vn
                    for _ in range(20):  # safety limit
                        desc = cur.loneDescend() if hasattr(cur, 'loneDescend') else None
                        if desc is None or desc.code() != OpCode.CPUI_PIECE:
                            break
                        outvn = desc.getOut()
                        if outvn is None:
                            break
                        rootVn = outvn
                        cur = outvn
                if vn is rootVn:
                    return -1
                rootDef = rootVn.getDef() if rootVn.isWritten() else None
                if rootDef is not None and hasattr(rootDef, 'isPartialRoot') and rootDef.isPartialRoot():
                    return -1
            else:
                return -1
        elif vn.isMapped():
            return -1
        elif vn.isProtoPartial():
            return -1
        else:
            from ghidra.core.opcodes import OpCode
            if defop.code() == OpCode.CPUI_PIECE and defop.getIn(0).isProtoPartial():
                return -1
        if vn.hasNoDescend():
            return -1  # Must have at least one descendant

        from ghidra.core.opcodes import OpCode
        if defop.code() == OpCode.CPUI_PTRSUB:
            basevn = defop.getIn(0)
            if basevn.isSpacebase():
                if basevn.isConstant() or basevn.isInput():
                    maxref = 1000000  # Should always be implicit
        desccount = 0
        for op in vn.getDescendants():
            if op.isMarker():
                return -1
            desccount += 1
            if desccount > maxref:
                return -1  # Must not exceed max descendants
        return desccount

    @staticmethod
    def multipleInteraction(multlist: list) -> int:
        """Check for implied varnodes with multiple descendants that interact.

        C++ ref: ``ActionMarkExplicit::multipleInteraction``
        """
        from ghidra.core.opcodes import OpCode
        purgelist = []
        for vn in multlist:
            defop = vn.getDef()
            if defop is None:
                continue
            opc = defop.code()
            if defop.isBoolOutput() or opc == OpCode.CPUI_INT_ZEXT or opc == OpCode.CPUI_INT_SEXT or opc == OpCode.CPUI_PTRADD:
                maxparam = min(2, defop.numInput())
                for j in range(maxparam):
                    topvn = defop.getIn(j)
                    if topvn.isMark():
                        topopc = OpCode.CPUI_COPY
                        if topvn.isWritten():
                            if topvn.getDef().isBoolOutput():
                                continue  # Try not to make boolean outputs explicit
                            topopc = topvn.getDef().code()
                        if opc == OpCode.CPUI_PTRADD:
                            if topopc == OpCode.CPUI_PTRADD:
                                purgelist.append(topvn)
                        else:
                            purgelist.append(topvn)
        for vn in purgelist:
            vn.setExplicit()
            vn.clearImplied()
            vn.clearMark()
        return len(purgelist)

    @staticmethod
    def processMultiplier(vn, maxdup: int) -> None:
        """Count terms in expression; if > maxdup, mark vn as explicit.

        C++ ref: ``ActionMarkExplicit::processMultiplier``
        """
        # Depth-first traversal along op inputs
        # Each stack element: (varnode, slot, slotback)
        from ghidra.core.opcodes import OpCode
        stack = []

        def _make_elem(v):
            s = 0
            sb = 0
            if v.isWritten():
                opc = v.getDef().code()
                if opc == OpCode.CPUI_LOAD:
                    s = 1; sb = 2
                elif opc == OpCode.CPUI_PTRADD:
                    sb = 1
                else:
                    sb = v.getDef().numInput()
            return [v, s, sb]

        stack.append(_make_elem(vn))
        finalcount = 0
        while stack:
            elem = stack[-1]
            vncur = elem[0]
            isaterm = vncur.isExplicit() or not vncur.isWritten()
            if isaterm or elem[2] <= elem[1]:  # Trimming condition
                if isaterm:
                    if not vncur.isSpacebase():
                        finalcount += 1
                if finalcount > maxdup:
                    vn.setExplicit()
                    vn.clearImplied()
                    return
                stack.pop()
            else:
                op = vncur.getDef()
                newvn = op.getIn(elem[1])
                elem[1] += 1
                if newvn is None or newvn.isMark():
                    vn.setExplicit()
                    vn.clearImplied()
                    return
                stack.append(_make_elem(newvn))

    @staticmethod
    def checkNewToConstructor(data, vn) -> None:
        """Check if CPUI_NEW feeds a constructor call.

        C++ ref: ``ActionMarkExplicit::checkNewToConstructor``
        """
        from ghidra.core.opcodes import OpCode
        defop = vn.getDef()
        if defop is None:
            return
        bb = defop.getParent()
        if bb is None:
            return
        firstuse = None
        for curop in vn.getDescendants():
            if curop.getParent() is not bb:
                continue
            if firstuse is None:
                firstuse = curop
            elif hasattr(curop, 'getSeqNum') and hasattr(firstuse, 'getSeqNum'):
                if curop.getSeqNum().getOrder() < firstuse.getSeqNum().getOrder():
                    firstuse = curop
        if firstuse is None:
            return
        if not firstuse.isCall():
            return
        if firstuse.getOut() is not None:
            return
        if firstuse.numInput() < 2:
            return
        if firstuse.getIn(1) is not vn:
            return
        if hasattr(data, 'opMarkSpecialPrint'):
            data.opMarkSpecialPrint(firstuse)
        if hasattr(data, 'opMarkNonPrinting'):
            data.opMarkNonPrinting(defop)

    def apply(self, data):
        multlist = []  # implied varnodes with >1 descendants
        maxref = getattr(data.getArch(), 'max_implied_ref', 20) if data.getArch() is not None else 20

        for vn in list(data._vbank.beginDef()):
            if vn.isFree():
                continue
            desccount = ActionMarkExplicit.baseExplicit(vn, maxref)
            if desccount < 0:
                vn.setExplicit()
                self._count += 1
                if desccount < -1:
                    ActionMarkExplicit.checkNewToConstructor(data, vn)
            elif desccount > 1:
                vn.setMark()
                multlist.append(vn)

        self._count += ActionMarkExplicit.multipleInteraction(multlist)
        maxdup = getattr(data.getArch(), 'max_term_duplication', 16) if data.getArch() is not None else 16
        for vn in multlist:
            if vn.isMark():
                ActionMarkExplicit.processMultiplier(vn, maxdup)
        for vn in multlist:
            vn.clearMark()
        return 0

class ActionMarkImplied(Action):
    """Mark Varnodes that can be printed as implied (inline) expressions.

    C++ ref: ``ActionMarkImplied`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markimplied", g)
    def clone(self, gl):
        return ActionMarkImplied(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def isPossibleAliasStep(vn1, vn2) -> bool:
        """Return False only if one Varnode is obtained by adding non-zero to another."""
        from ghidra.core.opcodes import OpCode
        for va, vb in [(vn1, vn2), (vn2, vn1)]:
            if not va.isWritten():
                continue
            op = va.getDef()
            opc = op.code()
            if opc not in (OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB, OpCode.CPUI_PTRADD, OpCode.CPUI_INT_XOR):
                continue
            if vb is not op.getIn(0):
                continue
            if op.getIn(1).isConstant():
                return False
        return True

    @staticmethod
    def isPossibleAlias(vn1, vn2, depth: int) -> bool:
        """Return False only if we can guarantee two Varnodes have different values."""
        from ghidra.core.opcodes import OpCode
        if vn1 is vn2:
            return True
        if not vn1.isWritten() or not vn2.isWritten():
            if vn1.isConstant() and vn2.isConstant():
                return vn1.getOffset() == vn2.getOffset()
            return ActionMarkImplied.isPossibleAliasStep(vn1, vn2)
        if not ActionMarkImplied.isPossibleAliasStep(vn1, vn2):
            return False
        op1 = vn1.getDef()
        op2 = vn2.getDef()
        opc1 = op1.code()
        opc2 = op2.code()
        mult1 = 1
        mult2 = 1
        if opc1 == OpCode.CPUI_PTRSUB:
            opc1 = OpCode.CPUI_INT_ADD
        elif opc1 == OpCode.CPUI_PTRADD:
            opc1 = OpCode.CPUI_INT_ADD
            mult1 = int(op1.getIn(2).getOffset()) if op1.numInput() > 2 else 1
        if opc2 == OpCode.CPUI_PTRSUB:
            opc2 = OpCode.CPUI_INT_ADD
        elif opc2 == OpCode.CPUI_PTRADD:
            opc2 = OpCode.CPUI_INT_ADD
            mult2 = int(op2.getIn(2).getOffset()) if op2.numInput() > 2 else 1
        if opc1 != opc2:
            return True
        if depth == 0:
            return True
        depth -= 1
        if opc1 in (OpCode.CPUI_COPY, OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT,
                    OpCode.CPUI_INT_2COMP, OpCode.CPUI_INT_NEGATE):
            return ActionMarkImplied.isPossibleAlias(op1.getIn(0), op2.getIn(0), depth)
        if opc1 == OpCode.CPUI_INT_ADD:
            from ghidra.core.expression import functionalEquality
            cvn1 = op1.getIn(1)
            cvn2 = op2.getIn(1)
            if cvn1.isConstant() and cvn2.isConstant():
                val1 = mult1 * cvn1.getOffset()
                val2 = mult2 * cvn2.getOffset()
                if val1 == val2:
                    return ActionMarkImplied.isPossibleAlias(op1.getIn(0), op2.getIn(0), depth)
                return not functionalEquality(op1.getIn(0), op2.getIn(0))
            if mult1 != mult2:
                return True
            if functionalEquality(op1.getIn(0), op2.getIn(0)):
                return ActionMarkImplied.isPossibleAlias(op1.getIn(1), op2.getIn(1), depth)
            if functionalEquality(op1.getIn(1), op2.getIn(1)):
                return ActionMarkImplied.isPossibleAlias(op1.getIn(0), op2.getIn(0), depth)
            if functionalEquality(op1.getIn(0), op2.getIn(1)):
                return ActionMarkImplied.isPossibleAlias(op1.getIn(1), op2.getIn(0), depth)
            if functionalEquality(op1.getIn(1), op2.getIn(0)):
                return ActionMarkImplied.isPossibleAlias(op1.getIn(0), op2.getIn(1), depth)
        return True

    @staticmethod
    def checkImpliedCover(data, vn) -> bool:
        """Check if marking vn as implied would cause a Cover violation.

        C++ ref: ``ActionMarkImplied::checkImpliedCover``
        """
        op = vn.getDef()
        if op is None:
            return True
        from ghidra.core.opcodes import OpCode
        # Check loads crossing stores
        if op.code() == OpCode.CPUI_LOAD:
            cover = vn.getCover() if hasattr(vn, 'getCover') and vn.hasCover() else None
            if cover is not None:
                for storeop in list(data._obank.beginAlive()):
                    if storeop.isDead():
                        continue
                    if storeop.code() != OpCode.CPUI_STORE:
                        continue
                    if hasattr(cover, 'contain') and cover.contain(storeop, 2):
                        if storeop.getIn(0).getOffset() == op.getIn(0).getOffset():
                            if ActionMarkImplied.isPossibleAlias(
                                    storeop.getIn(1), op.getIn(1), 2):
                                return False
        # Check loads/calls crossing calls
        if op.isCall() or op.code() == OpCode.CPUI_LOAD:
            cover = vn.getCover() if hasattr(vn, 'getCover') and vn.hasCover() else None
            if cover is not None:
                for i in range(data.numCalls()):
                    callop = data.getCallSpecs(i).getOp()
                    if hasattr(cover, 'contain') and cover.contain(callop, 2):
                        return False
        # Check input intersection
        for i in range(op.numInput()):
            defvn = op.getIn(i)
            if defvn is None:
                continue
            if defvn.isConstant():
                continue
            if hasattr(data, 'getMerge'):
                merger = data.getMerge()
                high = vn.getHigh()
                if high is not None and hasattr(merger, 'inflateTest'):
                    if merger.inflateTest(defvn, high):
                        return False
        return True

    def apply(self, data):
        from ghidra.analysis.merge import Merge
        for vn in list(data._vbank.beginLoc()):
            if vn.isFree():
                continue
            if vn.isExplicit():
                continue
            if vn.isImplied():
                continue
            # Depth-first traversal: process all descendants before marking current
            varstack = [(vn, iter(vn.getDescendants()))]
            while varstack:
                vncur, desciter = varstack[-1]
                op = next(desciter, None)
                if op is None:
                    # All descendants traced, mark this varnode
                    self._count += 1
                    if not ActionMarkImplied.checkImpliedCover(data, vncur):
                        vncur.setExplicit()
                    else:
                        Merge.markImplied(vncur)
                    varstack.pop()
                else:
                    outvn = op.getOut()
                    if outvn is not None and not outvn.isExplicit() and not outvn.isImplied():
                        varstack.append((outvn, iter(outvn.getDescendants())))
        return 0

class ActionMarkIndirectOnly(Action):
    """Mark Varnodes only used through INDIRECT as indirect-only."""
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "markindirectonly", g)
    def clone(self, gl):
        return ActionMarkIndirectOnly(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        from ghidra.ir.varnode import Varnode
        for vn in list(data._vbank.beginLoc()):
            if not (vn._flags & 0x10):
                continue
            allIndirect = True
            for desc in vn.getDescendants():
                if desc.code() != OpCode.CPUI_INDIRECT:
                    allIndirect = False
                    break
            if allIndirect and not vn.hasNoDescend():
                vn._flags |= Varnode.indirectonly
        return 0

class ActionNameVars(Action):
    """Assign names to high-level variables.

    C++ ref: ``ActionNameVars`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "namevars", g)
    def clone(self, gl):
        return ActionNameVars(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def linkSpacebaseSymbol(vn, data, namerec: list) -> None:
        """Link symbols associated with a spacebase Varnode."""
        from ghidra.core.opcodes import OpCode
        if not vn.isConstant() and not vn.isInput():
            return
        for op in vn.getDescendants():
            if op.code() != OpCode.CPUI_PTRSUB:
                continue
            offVn = op.getIn(1)
            if hasattr(data, 'linkSymbolReference'):
                sym = data.linkSymbolReference(offVn)
                if sym is not None and hasattr(sym, 'isNameUndefined') and sym.isNameUndefined():
                    namerec.append(offVn)

    @staticmethod
    def linkSymbols(data, namerec: list) -> None:
        """Link formal Symbols to their HighVariable representatives."""
        arch = data.getArch()
        if arch is None:
            return
        constSpace = arch.getConstantSpace() if hasattr(arch, 'getConstantSpace') else None

        # Link constant-space spacebase symbols
        if constSpace is not None:
            for vn in list(data._vbank.beginLoc()):
                spc = vn._loc.base
                if spc is not constSpace:
                    continue
                if hasattr(vn, 'getSymbolEntry') and vn.getSymbolEntry() is not None:
                    if hasattr(data, 'linkSymbol'):
                        data.linkSymbol(vn)
                elif vn.isSpacebase():
                    ActionNameVars.linkSpacebaseSymbol(vn, data, namerec)

        # Link non-constant space symbols
        for vn in list(data._vbank.beginLoc()):
            if vn.isFree():
                continue
            spc = vn.getSpace()
            if constSpace is not None and spc is constSpace:
                continue
            if vn.isSpacebase():
                ActionNameVars.linkSpacebaseSymbol(vn, data, namerec)
            high = vn.getHigh()
            if high is None:
                continue
            nameRep = high.getNameRepresentative() if hasattr(high, 'getNameRepresentative') else vn
            if nameRep is not vn:
                continue
            try:
                has_name = high.hasName() if hasattr(high, 'hasName') else False
            except RuntimeError:
                continue
            if not has_name:
                continue
            if hasattr(data, 'linkSymbol'):
                sym = data.linkSymbol(vn)
                if sym is not None:
                    if hasattr(sym, 'isNameUndefined') and sym.isNameUndefined():
                        symoff = high.getSymbolOffset() if hasattr(high, 'getSymbolOffset') else -1
                        if symoff < 0:
                            namerec.append(vn)

    @staticmethod
    def lookForBadJumpTables(data) -> None:
        """Name putative switch variables for unrecovered jump tables."""
        from ghidra.core.opcodes import OpCode
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if localmap is None:
            return
        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if not hasattr(fc, 'isBadJumpTable') or not fc.isBadJumpTable():
                continue
            op = fc.getOp()
            vn = op.getIn(0)
            if vn.isImplied() and vn.isWritten():
                castop = vn.getDef()
                if castop.code() == OpCode.CPUI_CAST:
                    vn = castop.getIn(0)
            if vn.isFree():
                continue
            high = vn.getHigh()
            if high is None:
                continue
            sym = high.getSymbol() if hasattr(high, 'getSymbol') else None
            if sym is None:
                continue
            if hasattr(sym, 'isNameLocked') and sym.isNameLocked():
                continue
            if hasattr(sym, 'getScope') and sym.getScope() is not localmap:
                continue
            if hasattr(localmap, 'makeNameUnique') and hasattr(sym.getScope(), 'renameSymbol'):
                newname = localmap.makeNameUnique("UNRECOVERED_JUMPTABLE")
                sym.getScope().renameSymbol(sym, newname)

    @staticmethod
    def makeRec(param, vn, recmap: dict) -> None:
        """Add a recommendation based on a sub-function parameter."""
        from ghidra.core.opcodes import OpCode
        if not hasattr(param, 'isNameLocked') or not param.isNameLocked():
            return
        if hasattr(param, 'isNameUndefined') and param.isNameUndefined():
            return
        if vn.getSize() != param.getSize():
            return
        ct = param.getType() if hasattr(param, 'getType') else None
        if vn.isImplied() and vn.isWritten():
            castop = vn.getDef()
            if castop.code() == OpCode.CPUI_CAST:
                vn = castop.getIn(0)
                ct = None  # Less preferred name
        high = vn.getHigh()
        if high is None:
            return
        if high.isAddrTied() if hasattr(high, 'isAddrTied') else False:
            return
        name = param.getName()
        if name.startswith("param_"):
            return
        hid = id(high)
        if hid in recmap:
            if ct is None:
                return
            old = recmap[hid]
            if old[1] is not None:
                if hasattr(old[1], 'typeOrder') and old[1].typeOrder(ct) <= 0:
                    return
            recmap[hid] = (name, ct, high)
        else:
            recmap[hid] = (name, ct, high)

    @staticmethod
    def lookForFuncParamNames(data, varlist: list) -> None:
        """Collect variable names from sub-function parameters."""
        numfunc = data.numCalls()
        if numfunc == 0:
            return
        recmap = {}  # id(HighVariable) -> (name, type, high)
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if localmap is None:
            return
        for i in range(numfunc):
            fc = data.getCallSpecs(i)
            if not fc.isInputLocked():
                continue
            op = fc.getOp()
            numparam = fc.numParams()
            if numparam >= op.numInput():
                numparam = op.numInput() - 1
            for j in range(numparam):
                param = fc.getParam(j)
                vn = op.getIn(j + 1)
                ActionNameVars.makeRec(param, vn, recmap)
        if not recmap:
            return
        for vn in varlist:
            if vn.isFree() or vn.isInput():
                continue
            high = vn.getHigh()
            if high is None:
                continue
            if hasattr(high, 'getNumMergeClasses') and high.getNumMergeClasses() > 1:
                continue
            sym = high.getSymbol() if hasattr(high, 'getSymbol') else None
            if sym is None:
                continue
            if not (hasattr(sym, 'isNameUndefined') and sym.isNameUndefined()):
                continue
            hid = id(high)
            if hid in recmap:
                newname, _, _ = recmap[hid]
                if hasattr(localmap, 'makeNameUnique') and hasattr(sym.getScope(), 'renameSymbol'):
                    sym.getScope().renameSymbol(sym, localmap.makeNameUnique(newname))

    def apply(self, data):
        namerec = []
        ActionNameVars.linkSymbols(data, namerec)
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if localmap is not None and hasattr(localmap, 'recoverNameRecommendationsForSymbols'):
            localmap.recoverNameRecommendationsForSymbols()
        ActionNameVars.lookForBadJumpTables(data)
        ActionNameVars.lookForFuncParamNames(data, namerec)

        base = 1
        for vn in namerec:
            high = vn.getHigh()
            if high is None:
                continue
            sym = high.getSymbol() if hasattr(high, 'getSymbol') else None
            if sym is None:
                continue
            if hasattr(sym, 'isNameUndefined') and sym.isNameUndefined():
                scope = sym.getScope() if hasattr(sym, 'getScope') else None
                if scope is not None and hasattr(scope, 'buildDefaultName'):
                    newname = scope.buildDefaultName(sym, base, vn)
                    if hasattr(scope, 'renameSymbol'):
                        scope.renameSymbol(sym, newname)
                    base += 1
        if localmap is not None and hasattr(localmap, 'assignDefaultNames'):
            localmap.assignDefaultNames(base)
        return 0

class ActionSetCasts(Action):
    """Insert CAST operations where type conversions are needed.

    C++ ref: ``ActionSetCasts::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "setcasts", g)
    def clone(self, gl):
        return ActionSetCasts(self._basegroup) if gl.contains(self._basegroup) else None

    @staticmethod
    def castInput(op, slot: int, data, castStrategy) -> int:
        """Attempt to insert a CAST on input slot of op."""
        from ghidra.core.opcodes import OpCode
        if castStrategy is None:
            return 0
        vn = op.getIn(slot)
        if vn is None:
            return 0
        # Get the required input type from the op's TypeOp
        reqtype = None
        if hasattr(op, 'getInputLocal') and hasattr(op.getInputLocal(), 'getInputCast'):
            reqtype = op.getInputLocal().getInputCast(slot, op, castStrategy)
        if reqtype is None:
            return 0
        # Insert a CAST
        if hasattr(data, 'opInsertCast'):
            data.opInsertCast(op, slot, reqtype)
            return 1
        return 0

    @staticmethod
    def castOutput(op, data, castStrategy) -> int:
        """Attempt to insert a CAST on output of op."""
        if castStrategy is None:
            return 0
        vn = op.getOut()
        if vn is None:
            return 0
        outtype = None
        if hasattr(op, 'getInputLocal') and hasattr(op.getInputLocal(), 'getOutputToken'):
            outtype = op.getInputLocal().getOutputToken(op, castStrategy)
        if outtype is None:
            return 0
        # Would insert output cast
        return 0

    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        data.startCastPhase()
        castStrategy = None
        arch = data.getArch()
        if arch is not None:
            if hasattr(arch, 'print') and arch.print is not None:
                if hasattr(arch.print, 'getCastStrategy'):
                    castStrategy = arch.print.getCastStrategy()

        # Walk basic blocks in order
        bblocks = data.getBasicBlocks() if hasattr(data, 'getBasicBlocks') else None
        if bblocks is None:
            return 0
        for j in range(bblocks.getSize()):
            bb = bblocks.getBlock(j)
            if bb is None:
                continue
            for op in list(bb.beginOp()):
                if op.notPrinted():
                    continue
                opc = op.code()
                if opc == OpCode.CPUI_CAST:
                    continue
                if opc == OpCode.CPUI_PTRADD:
                    # Check if PTRADD still fits its pointer
                    if op.numInput() > 2 and op.getIn(2).isConstant():
                        sz = int(op.getIn(2).getOffset())
                        invn = op.getIn(0)
                        ct = invn.getHighTypeReadFacing(op) if hasattr(invn, 'getHighTypeReadFacing') else None
                        if ct is not None and hasattr(ct, 'getMetatype'):
                            from ghidra.types.datatype import TYPE_PTR
                            if ct.getMetatype() != TYPE_PTR:
                                if hasattr(data, 'opUndoPtradd'):
                                    data.opUndoPtradd(op, True)
                elif opc == OpCode.CPUI_PTRSUB:
                    invn = op.getIn(0)
                    ct = invn.getTypeReadFacing(op) if hasattr(invn, 'getTypeReadFacing') else None
                    if ct is not None and hasattr(ct, 'isPtrsubMatching'):
                        if not ct.isPtrsubMatching(op.getIn(1).getOffset(), 0, 0):
                            if op.getIn(1).getOffset() == 0:
                                data.opRemoveInput(op, 1)
                                data.opSetOpcode(op, OpCode.CPUI_COPY)
                            else:
                                data.opSetOpcode(op, OpCode.CPUI_INT_ADD)

                # Do input casts first, as output may depend on input
                for i in range(op.numInput()):
                    self._count += ActionSetCasts.castInput(op, i, data, castStrategy)

                vn = op.getOut()
                if vn is None:
                    continue
                self._count += ActionSetCasts.castOutput(op, data, castStrategy)
        return 0

class ActionDominantCopy(Action):
    """Replace COPYs from the same source with a single dominant COPY.

    C++ ref: ``ActionDominantCopy::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "dominantcopy", g)
    def clone(self, gl):
        return ActionDominantCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'processCopyTrims'):
            merge.processCopyTrims()
        return 0

class ActionDynamicSymbols(Action):
    """Map dynamic hash-based symbols to their Varnodes (late pass).

    C++ ref: ``ActionDynamicSymbols::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "dynamicsymbols", g)
    def clone(self, gl):
        return ActionDynamicSymbols(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        localmap = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if localmap is None:
            return 0
        if not hasattr(localmap, 'beginDynamic'):
            return 0
        from ghidra.analysis.dynamic import DynamicHash
        dhash = DynamicHash()
        entries = list(localmap.beginDynamic())
        for entry in entries:
            if hasattr(data, 'attemptDynamicMappingLate'):
                if data.attemptDynamicMappingLate(entry, dhash):
                    self._count += 1
        return 0

class ActionCopyMarker(Action):
    """Mark COPY operations between Varnodes representing the same object as non-printing.

    C++ ref: ``ActionCopyMarker::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "copymarker", g)
    def clone(self, gl):
        return ActionCopyMarker(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        if merge is not None and hasattr(merge, 'markInternalCopies'):
            merge.markInternalCopies()
        return 0

class ActionHideShadow(Action):
    """Hide shadow copies of input varnodes that were saved/restored.

    C++ ref: ``ActionHideShadow::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "hideshadow", g)
    def clone(self, gl):
        return ActionHideShadow(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        merge = data.getMerge() if hasattr(data, 'getMerge') else None
        allvn = [vn for vn in data._vbank.beginDef() if vn._flags & 0x10]
        # First pass: hide shadows on each unique HighVariable
        for vn in allvn:
            high = vn.getHigh()
            if high is None:
                continue
            if hasattr(high, 'isMark') and high.isMark():
                continue
            if merge is not None and hasattr(merge, 'hideShadows'):
                if merge.hideShadows(high):
                    self._count += 1
            if hasattr(high, 'setMark'):
                high.setMark()
        # Second pass: clear marks
        for vn in allvn:
            high = vn.getHigh()
            if high is not None and hasattr(high, 'clearMark'):
                high.clearMark()
        return 0

class ActionOutputPrototype(Action):
    """Determine the output prototype from RETURN operations.

    C++ ref: ``ActionOutputPrototype::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "outputprototype", g)
    def clone(self, gl):
        return ActionOutputPrototype(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        proto = data.getFuncProto()
        outparam = proto.getOutput()
        if outparam is None:
            return 0
        if not outparam.isTypeLocked() or (hasattr(outparam, 'isSizeTypeLocked') and outparam.isSizeTypeLocked()):
            op = data.getFirstReturnOp() if hasattr(data, 'getFirstReturnOp') else None
            vnlist = []
            if op is not None:
                for i in range(1, op.numInput()):
                    vnlist.append(op.getIn(i))
            if hasattr(data, 'isHighOn') and data.isHighOn():
                if hasattr(proto, 'updateOutputTypes'):
                    proto.updateOutputTypes(vnlist)
            else:
                if hasattr(proto, 'updateOutputNoTypes'):
                    glb = data.getArch()
                    tfact = glb.types if glb is not None and hasattr(glb, 'types') else None
                    proto.updateOutputNoTypes(vnlist, tfact)
        return 0

class ActionInputPrototype(Action):
    """Finalize the input prototype based on actually used input varnodes.

    C++ ref: ``ActionInputPrototype::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "inputprototype", g)
    def clone(self, gl):
        return ActionInputPrototype(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.fspec.paramactive import ParamActive
        proto = data.getFuncProto()
        if hasattr(data, 'getScopeLocal') and data.getScopeLocal() is not None:
            localmap = data.getScopeLocal()
            if hasattr(localmap, 'clearCategory'):
                localmap.clearCategory(0)  # Symbol::fake_input = 0
        if hasattr(proto, 'clearUnlockedInput'):
            proto.clearUnlockedInput()
        if not proto.isInputLocked():
            triallist = []
            active = ParamActive(False)
            from ghidra.ir.varnode import Varnode
            for vn in list(data._vbank.beginDef()):
                if not vn.isInput():
                    continue
                if hasattr(proto, 'possibleInputParam') and proto.possibleInputParam(vn.getAddr(), vn.getSize()):
                    slot = active.getNumTrials()
                    active.registerTrial(vn.getAddr(), vn.getSize())
                    if not vn.hasNoDescend():
                        active.getTrial(slot).markActive()
                    triallist.append(vn)
            if hasattr(proto, 'resolveModel'):
                proto.resolveModel(active)
            if hasattr(proto, 'deriveInputMap'):
                proto.deriveInputMap(active)
            # Create unreferenced input varnodes
            for i in range(active.getNumTrials()):
                trial = active.getTrial(i)
                if hasattr(trial, 'isUnref') and trial.isUnref() and hasattr(trial, 'isUsed') and trial.isUsed():
                    if hasattr(data, 'hasInputIntersection') and data.hasInputIntersection(trial.getSize(), trial.getAddress()):
                        trial.markNoUse()
                    else:
                        vn = data.newVarnode(trial.getSize(), trial.getAddress())
                        if hasattr(data, 'setInputVarnode'):
                            vn = data.setInputVarnode(vn)
                        slot = len(triallist)
                        triallist.append(vn)
                        trial.setSlot(slot + 1)
            if hasattr(data, 'isHighOn') and data.isHighOn():
                if hasattr(proto, 'updateInputTypes'):
                    proto.updateInputTypes(data, triallist, active)
            else:
                if hasattr(proto, 'updateInputNoTypes'):
                    proto.updateInputNoTypes(data, triallist, active)
        data.clearDeadVarnodes()
        return 0

class ActionMapGlobals(Action):
    """Create symbols for any discovered global variables in the function.

    C++ ref: ``ActionMapGlobals::apply`` in coreaction.hh
    """
    def __init__(self, g): super().__init__(Action.rule_onceperfunc, "mapglobals", g)
    def clone(self, gl):
        return ActionMapGlobals(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        if hasattr(data, 'mapGlobals'):
            data.mapGlobals()
        return 0

class ActionMappedLocalSync(Action):
    """Synchronize mapped local variables with their symbols.

    C++ ref: ``ActionMappedLocalSync::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "mapped_local_sync", g)
    def clone(self, gl):
        return ActionMappedLocalSync(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        l1 = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if l1 is None:
            return 0
        if hasattr(data, 'syncVarnodesWithSymbols'):
            if data.syncVarnodesWithSymbols(l1, True, True):
                self._count += 1
        if hasattr(l1, 'hasOverlapProblems') and l1.hasOverlapProblems():
            if hasattr(data, 'warningHeader'):
                data.warningHeader("Could not reconcile some variable overlaps")
        return 0

class ActionPrototypeWarnings(Action):
    """Emit warnings about prototype issues (missing returns, bad params).

    C++ ref: ``ActionPrototypeWarnings::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "prototypewarnings", g)
    def clone(self, gl):
        return ActionPrototypeWarnings(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        # Generate override messages
        if hasattr(data, 'getOverride'):
            override = data.getOverride()
            if hasattr(override, 'generateOverrideMessages'):
                try:
                    msgs = override.generateOverrideMessages(data.getArch())
                    if isinstance(msgs, list):
                        for msg in msgs:
                            if hasattr(data, 'warningHeader'):
                                data.warningHeader(msg)
                except TypeError:
                    pass

        proto = data.getFuncProto()
        if hasattr(proto, 'hasInputErrors') and proto.hasInputErrors():
            if hasattr(data, 'warningHeader'):
                data.warningHeader("Cannot assign parameter locations for this function: Prototype may be inaccurate")
        if hasattr(proto, 'hasOutputErrors') and proto.hasOutputErrors():
            if hasattr(data, 'warningHeader'):
                data.warningHeader("Cannot assign location of return value for this function: Return value may be inaccurate")
        if hasattr(proto, 'isModelUnknown') and proto.isModelUnknown():
            msg = "Unknown calling convention"
            if hasattr(proto, 'printModelInDecl') and proto.printModelInDecl():
                msg += ": " + (proto.getModelName() if hasattr(proto, 'getModelName') else "?")
            if not (hasattr(proto, 'hasCustomStorage') and proto.hasCustomStorage()):
                if proto.isInputLocked() or proto.isOutputLocked():
                    msg += " -- yet parameter storage is locked"
            if hasattr(data, 'warningHeader'):
                data.warningHeader(msg)

        for i in range(data.numCalls()):
            fc = data.getCallSpecs(i)
            if fc is None:
                continue
            if hasattr(fc, 'hasInputErrors') and fc.hasInputErrors():
                fname = "<indirect>"
                if hasattr(fc, 'getFuncdata') and fc.getFuncdata() is not None:
                    fname = fc.getFuncdata().getName()
                if hasattr(data, 'warning'):
                    data.warning(f"Cannot assign parameter location for function {fname}: Prototype may be inaccurate",
                                 fc.getEntryAddress())
            if hasattr(fc, 'hasOutputErrors') and fc.hasOutputErrors():
                fname = "<indirect>"
                if hasattr(fc, 'getFuncdata') and fc.getFuncdata() is not None:
                    fname = fc.getFuncdata().getName()
                if hasattr(data, 'warning'):
                    data.warning(f"Cannot assign location of return value for function {fname}: Return value may be inaccurate",
                                 fc.getEntryAddress())
        return 0

# --- Block structure Actions (stubs) ---

class ActionBlockStructure(Action):
    """Structure control-flow using standard high-level code constructs.

    C++ ref: ``ActionBlockStructure::apply`` in blockaction.cc
    """
    def __init__(self, g): super().__init__(0, "blockstructure", g)
    def clone(self, gl):
        return ActionBlockStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph.getSize() != 0:
            return 0
        if hasattr(data, 'installSwitchDefaults'):
            data.installSwitchDefaults()
        graph.buildCopy(data.getBasicBlocks())
        from ghidra.block.blockaction import CollapseStructure
        collapse = CollapseStructure(graph)
        collapse.collapseAll()
        self._count += collapse.getChangeCount()
        return 0

class ActionNodeJoin(Action):
    """Join basic blocks where a conditional branch has been split.

    C++ ref: ``ActionNodeJoin::apply`` in blockaction.cc
    """
    def __init__(self, g): super().__init__(0, "nodejoin", g)
    def clone(self, gl):
        return ActionNodeJoin(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getBasicBlocks()
        if graph is None or graph.getSize() == 0:
            return 0
        condjoin = None
        try:
            from ghidra.block.blockaction import ConditionalJoin
            condjoin = ConditionalJoin(data)
        except (ImportError, Exception):
            pass
        if condjoin is None:
            return 0
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if bb.sizeOut() != 2:
                continue
            out1 = bb.getOut(0)
            out2 = bb.getOut(1)
            if out1.sizeIn() < out2.sizeIn():
                leastout = out1
                inslot = bb.getOutRevIndex(0)
            else:
                leastout = out2
                inslot = bb.getOutRevIndex(1)
            if leastout.sizeIn() == 1:
                continue
            for j in range(leastout.sizeIn()):
                if j == inslot:
                    continue
                bb2 = leastout.getIn(j)
                if condjoin.match(bb, bb2):
                    self._count += 1
                    condjoin.execute()
                    condjoin.clear()
                    break
        return 0

class ActionConditionalExe(Action):
    """Remove redundant CBRANCHs that test the same condition as an earlier branch."""
    def __init__(self, g): super().__init__(0, "conditionalexe", g)
    def clone(self, gl):
        return ActionConditionalExe(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.transform.condexe import ConditionalExecution
        condexe = ConditionalExecution(data)
        graph = data.getBasicBlocks()
        changed = True
        while changed:
            changed = False
            for i in range(graph.getSize()):
                bb = graph.getBlock(i)
                if condexe.trial(bb):
                    condexe.execute()
                    self._count += 1
                    changed = True
                    break
        return 0

class ActionPreferComplement(Action):
    """Choose preferred complement for symmetric if/else structuring.

    C++ ref: ``ActionPreferComplement::apply`` in blockaction.cc
    """
    def __init__(self, g): super().__init__(0, "prefercomplement", g)
    def clone(self, gl):
        return ActionPreferComplement(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph is None or graph.getSize() == 0:
            return 0
        vec = [graph]
        pos = 0
        while pos < len(vec):
            curbl = vec[pos]
            pos += 1
            if not hasattr(curbl, 'getSize'):
                continue
            sz = curbl.getSize()
            for i in range(sz):
                childbl = curbl.getBlock(i)
                if hasattr(childbl, 'getSize'):
                    vec.append(childbl)
            if hasattr(curbl, 'preferComplement') and curbl.preferComplement(data):
                self._count += 1
        if hasattr(data, 'clearDeadOps'):
            data.clearDeadOps()
        return 0

class ActionStructureTransform(Action):
    """Give each structure element a chance to do final transforms (e.g. for-loop setup).

    C++ ref: ``ActionStructureTransform::apply`` in blockaction.cc
    """
    def __init__(self, g): super().__init__(0, "structuretransform", g)
    def clone(self, gl):
        return ActionStructureTransform(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph is None or graph.getSize() == 0:
            return 0
        vec = [graph]
        pos = 0
        while pos < len(vec):
            curbl = vec[pos]
            pos += 1
            if not hasattr(curbl, 'getSize'):
                continue
            sz = curbl.getSize()
            for i in range(sz):
                childbl = curbl.getBlock(i)
                if hasattr(childbl, 'getSize'):
                    vec.append(childbl)
            if hasattr(curbl, 'finalTransform') and curbl.finalTransform(data):
                self._count += 1
        return 0

class ActionNormalizeBranches(Action):
    """Normalize CBRANCH conditions for cleaner structured output."""
    def __init__(self, g): super().__init__(0, "normalizebranches", g)
    def clone(self, gl):
        return ActionNormalizeBranches(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        from ghidra.core.opcodes import OpCode
        graph = data.getBasicBlocks()
        for i in range(graph.getSize()):
            bb = graph.getBlock(i)
            if bb.sizeOut() != 2:
                continue
            cbranch = bb.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            # Attempt to normalize: flip if the boolean input can be simplified
            # by removing a BOOL_NEGATE
            inv = cbranch.getIn(1)
            if inv.isWritten() and inv.getDef().code() == OpCode.CPUI_BOOL_NEGATE:
                # Flip the branch and remove the negate
                bb.negateCondition(True)
                self._count += 1
        return 0

class ActionFinalStructure(Action):
    """Finalize control-flow structure: order blocks, insert breaks/gotos.

    C++ ref: ``ActionFinalStructure::apply`` in coreaction.cc
    """
    def __init__(self, g): super().__init__(0, "finalstructure", g)
    def clone(self, gl):
        return ActionFinalStructure(self._basegroup) if gl.contains(self._basegroup) else None
    def apply(self, data):
        graph = data.getStructure()
        if graph is None or graph.getSize() == 0:
            return 0
        if hasattr(graph, 'orderBlocks'):
            graph.orderBlocks()
        if hasattr(graph, 'finalizePrinting'):
            graph.finalizePrinting(data)
        if hasattr(graph, 'scopeBreak'):
            graph.scopeBreak(-1, -1)
        if hasattr(graph, 'markUnstructured'):
            graph.markUnstructured()
        if hasattr(graph, 'markLabelBumpUp'):
            graph.markLabelBumpUp(False)
        return 0
