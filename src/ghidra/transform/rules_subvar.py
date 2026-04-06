"""
Rule batch 2d: remaining rules needed for universalAction wiring.

Contains stub implementations for rules whose supporting infrastructure
(SplitDatatype, StringSequence, SubfloatFlow, DoubleDatatype, etc.)
is not yet fully ported. Each rule has the correct getOpList so it can
be wired into the pipeline without errors.

C++ refs:
  - RuleOrPredicate       -> condexe.cc
  - RuleSubfloatConvert   -> subflow.cc
  - RuleDoubleLoad/Store/In/Out -> double.cc
  - RuleDumptyHumpLate    -> subflow.cc
  - RuleSplitCopy/Load/Store -> subflow.cc
  - RuleStringCopy/Store  -> constseq.cc
"""
from __future__ import annotations

import os

from ghidra.core.opcodes import OpCode
from ghidra.transform.ruleaction import Rule


def _parse_subvar_debug_addr_spec(spec: str) -> tuple[bool, set[int]]:
    spec = spec.strip()
    if not spec:
        return False, set()
    if spec == "*":
        return True, set()
    addrs: set[int] = set()
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            addrs.add(int(part, 0))
        except Exception:
            continue
    return False, addrs


_SUBVAR_DEBUG_ADDRS_ALL, _SUBVAR_DEBUG_ADDRS = _parse_subvar_debug_addr_spec(
    os.getenv("PYGHIDRA_SUBVAR_DEBUG_ADDRS", "")
)
_SUBVAR_DEBUG_ENABLED = _SUBVAR_DEBUG_ADDRS_ALL or bool(_SUBVAR_DEBUG_ADDRS)
_SUBVAR_DEBUG_LOG_PATH = os.getenv(
    "PYGHIDRA_SUBVAR_DEBUG_LOG",
    "D:/BIGAI/pyghidra/temp/python_subvar_debug.log",
)


def _subvar_debug_should_log(op) -> bool:
    if not _SUBVAR_DEBUG_ENABLED:
        return False
    try:
        off = op.getAddr().getOffset()
    except Exception:
        return False
    if _SUBVAR_DEBUG_ADDRS_ALL:
        return True
    return off in _SUBVAR_DEBUG_ADDRS


def _subvar_debug_log(op, message: str) -> None:
    if not _subvar_debug_should_log(op):
        return
    try:
        addr = f"{op.getAddr().getOffset():#x}"
    except Exception:
        addr = "?"
    try:
        seq = f"{op.getSeqNum().getOrder():#x}"
    except Exception:
        seq = "?"
    try:
        with open(_SUBVAR_DEBUG_LOG_PATH, "a", encoding="utf-8") as fp:
            fp.write(f"[subvar] addr={addr} seq={seq} {message}\n")
    except Exception:
        return


class RuleOrPredicate(Rule):
    """Replace INT_OR/INT_XOR on predicated values with a MULTIEQUAL.

    C++ ref: ``RuleOrPredicate::applyOp`` in condexe.cc
    Delegates to the full implementation in ghidra.transform.condexe.
    """
    def __init__(self, g):
        super().__init__(g, 0, "orpredicate")
        from ghidra.transform.condexe import RuleOrPredicate as _Impl
        self._impl = _Impl(g)
    def clone(self, gl):
        return RuleOrPredicate(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR]
    def applyOp(self, op, data):
        return self._impl.applyOp(op, data)


class RuleSubfloatConvert(Rule):
    """Convert FLOAT_FLOAT2FLOAT chains into smaller precision operations.

    C++ ref: ``RuleSubfloatConvert::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subfloat_convert")
    def clone(self, gl):
        return RuleSubfloatConvert(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_FLOAT_FLOAT2FLOAT]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubfloatFlow
        invn = op.getIn(0)
        outvn = op.getOut()
        insize = invn.getSize()
        outsize = outvn.getSize()
        if outsize > insize:
            subflow = SubfloatFlow(data, outvn, insize)
            if not subflow.doTrace():
                return 0
        else:
            subflow = SubfloatFlow(data, invn, outsize)
            if not subflow.doTrace():
                return 0
        return 1


class RuleDoubleLoad(Rule):
    """Combine two PIECE'd LOADs into a single wider LOAD.

    C++ ref: ``RuleDoubleLoad::applyOp`` in double.cc
    """
    def __init__(self, g): super().__init__(g, 0, "doubleload")
    def clone(self, gl):
        return RuleDoubleLoad(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        from ghidra.analysis.double import SplitVarnode
        piece0 = op.getIn(0)
        piece1 = op.getIn(1)
        if not piece0.isWritten():
            return 0
        if not piece1.isWritten():
            return 0
        load1 = piece1.getDef()
        if load1.code() != OpCode.CPUI_LOAD:
            return 0
        load0 = piece0.getDef()
        opc = load0.code()
        offset = 0
        if opc == OpCode.CPUI_SUBPIECE:
            if load0.getIn(1).getOffset() != 0:
                return 0
            vn0 = load0.getIn(0)
            if not vn0.isWritten():
                return 0
            offset = vn0.getSize() - piece0.getSize()
            load0 = vn0.getDef()
            opc = load0.code()
        if opc != OpCode.CPUI_LOAD:
            return 0
        result = SplitVarnode.testContiguousPointers(load0, load1)
        if not result[0]:
            return 0
        loadlo, loadhi, spc = result[1], result[2], result[3]
        latest = SplitVarnode.noWriteConflict(loadlo, loadhi, spc)
        if latest is None:
            return 0
        size = piece0.getSize() + piece1.getSize()
        newload = data.newOp(2, latest.getAddr())
        vnout = data.newUniqueOut(size, newload)
        spcvn = data.newVarnodeSpace(spc)
        data.opSetOpcode(newload, OpCode.CPUI_LOAD)
        data.opSetInput(newload, spcvn, 0)
        addrvn = loadlo.getIn(1)
        if hasattr(spc, 'isBigEndian') and spc.isBigEndian() and offset != 0:
            newadd = data.newOp(2, latest.getAddr())
            addout = data.newUniqueOut(addrvn.getSize(), newadd)
            data.opSetOpcode(newadd, OpCode.CPUI_INT_ADD)
            data.opSetInput(newadd, addrvn, 0)
            data.opSetInput(newadd, data.newConstant(addrvn.getSize(), offset), 1)
            data.opInsertAfter(newadd, latest)
            addrvn = addout
            latest = newadd
        data.opSetInput(newload, addrvn, 1)
        data.opInsertAfter(newload, latest)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, vnout, 0)
        return 1


class RuleDoubleStore(Rule):
    """Combine two narrower STOREs into a single wide STORE for double-precision.

    C++ ref: ``RuleDoubleStore::applyOp`` in double.cc
    """
    def __init__(self, g): super().__init__(g, 0, "doublestore")
    def clone(self, gl):
        return RuleDoubleStore(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_STORE]
    def applyOp(self, op, data):
        from ghidra.analysis.double import SplitVarnode
        vnlo = op.getIn(2)
        if not (hasattr(vnlo, 'isPrecisLo') and vnlo.isPrecisLo()):
            return 0
        if not vnlo.isWritten():
            return 0
        subpieceOpLo = vnlo.getDef()
        if subpieceOpLo.code() != OpCode.CPUI_SUBPIECE:
            return 0
        if subpieceOpLo.getIn(1).getOffset() != 0:
            return 0
        whole = subpieceOpLo.getIn(0)
        if whole.isFree():
            return 0
        for subpieceOpHi in whole.getDescend():
            if subpieceOpHi.code() != OpCode.CPUI_SUBPIECE:
                continue
            if subpieceOpHi is subpieceOpLo:
                continue
            hi_offset = int(subpieceOpHi.getIn(1).getOffset())
            if hi_offset != vnlo.getSize():
                continue
            vnhi = subpieceOpHi.getOut()
            if not (hasattr(vnhi, 'isPrecisHi') and vnhi.isPrecisHi()):
                continue
            if vnhi.getSize() != whole.getSize() - hi_offset:
                continue
            for storeOp2 in vnhi.getDescend():
                if storeOp2.code() != OpCode.CPUI_STORE:
                    continue
                if storeOp2.getIn(2) is not vnhi:
                    continue
                result = SplitVarnode.testContiguousPointers(storeOp2, op)
                if not result[0]:
                    continue
                storelo, storehi, spc = result[1], result[2], result[3]
                latest = SplitVarnode.noWriteConflict(storelo, storehi, spc)
                if latest is None:
                    continue
                newstore = data.newOp(3, latest.getAddr())
                spcvn = data.newVarnodeSpace(spc)
                data.opSetOpcode(newstore, OpCode.CPUI_STORE)
                data.opSetInput(newstore, spcvn, 0)
                addrvn = storelo.getIn(1)
                if addrvn.isConstant():
                    addrvn = data.newConstant(addrvn.getSize(), addrvn.getOffset())
                data.opSetInput(newstore, addrvn, 1)
                data.opSetInput(newstore, whole, 2)
                data.opInsertAfter(newstore, latest)
                data.opDestroy(op)
                data.opDestroy(storeOp2)
                return 1
        return 0


class RuleDoubleIn(Rule):
    """Mark SUBPIECE inputs feeding double-precision operations.

    C++ ref: ``RuleDoubleIn::applyOp`` in double.cc
    """
    def __init__(self, g): super().__init__(g, 0, "doublein")
    def clone(self, gl):
        return RuleDoubleIn(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        from ghidra.analysis.double import SplitVarnode
        outvn = op.getOut()
        if not (hasattr(outvn, 'isPrecisLo') and outvn.isPrecisLo()):
            if hasattr(outvn, 'isPrecisHi') and outvn.isPrecisHi():
                return 0
            return self._attemptMarking(outvn, op)
        if hasattr(data, 'hasUnreachableBlocks') and data.hasUnreachableBlocks():
            return 0
        splitvec = []
        SplitVarnode.wholeList(op.getIn(0), splitvec)
        if not splitvec:
            return 0
        for inv in splitvec:
            res = SplitVarnode.applyRuleIn(inv, data)
            if res != 0:
                return res
        return 0

    @staticmethod
    def _attemptMarking(vn, subpieceOp) -> int:
        """Mark hi/lo pieces if the SUBPIECE extracts exactly half of an arithmetic whole."""
        if subpieceOp.numInput() < 2:
            return 0
        whole = subpieceOp.getIn(0)
        if hasattr(whole, 'isTypeLock') and whole.isTypeLock():
            tp = whole.getType() if hasattr(whole, 'getType') else None
            if tp is not None and hasattr(tp, 'isPrimitiveWhole') and not tp.isPrimitiveWhole():
                return 0
        offset = int(subpieceOp.getIn(1).getOffset())
        if offset != vn.getSize():
            return 0
        if offset * 2 != whole.getSize():
            return 0
        if whole.isInput():
            if not (hasattr(whole, 'isTypeLock') and whole.isTypeLock()):
                return 0
        elif not whole.isWritten():
            return 0
        else:
            defop = whole.getDef()
            typeop = defop.getOpcode() if hasattr(defop, 'getOpcode') else None
            if typeop is not None:
                if not ((hasattr(typeop, 'isArithmeticOp') and typeop.isArithmeticOp()) or
                        (hasattr(typeop, 'isFloatingPointOp') and typeop.isFloatingPointOp())):
                    return 0
            else:
                return 0
        vnLo = None
        for desc in whole.getDescend():
            if desc.code() != OpCode.CPUI_SUBPIECE:
                continue
            if desc.getIn(1).getOffset() != 0:
                continue
            if desc.getOut().getSize() == vn.getSize():
                vnLo = desc.getOut()
                break
        if vnLo is None:
            return 0
        if hasattr(vnLo, 'setPrecisLo'):
            vnLo.setPrecisLo()
        if hasattr(vn, 'setPrecisHi'):
            vn.setPrecisHi()
        return 1


class RuleDoubleOut(Rule):
    """Combine PIECE outputs from double-precision operations.

    C++ ref: ``RuleDoubleOut::applyOp`` in double.cc
    """
    def __init__(self, g): super().__init__(g, 0, "doubleout")
    def clone(self, gl):
        return RuleDoubleOut(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_PIECE]
    def applyOp(self, op, data):
        from ghidra.analysis.double import SplitVarnode
        vnhi = op.getIn(0)
        vnlo = op.getIn(1)
        if not vnhi.isInput() or not vnlo.isInput():
            return 0
        if not (hasattr(vnhi, 'isPersist') and vnhi.isPersist()):
            return 0
        if not (hasattr(vnlo, 'isPersist') and vnlo.isPersist()):
            return 0
        if not (hasattr(vnhi, 'isPrecisHi') and vnhi.isPrecisHi()) or \
           not (hasattr(vnlo, 'isPrecisLo') and vnlo.isPrecisLo()):
            return self._attemptMarking(vnhi, vnlo, op)
        if hasattr(data, 'hasUnreachableBlocks') and data.hasUnreachableBlocks():
            return 0
        ok, addr = SplitVarnode.isAddrTiedContiguous(vnlo, vnhi)
        if not ok:
            return 0
        if hasattr(data, 'combineInputVarnodes'):
            data.combineInputVarnodes(vnhi, vnlo)
        return 1

    @staticmethod
    def _attemptMarking(vnhi, vnlo, pieceOp) -> int:
        """Mark hi/lo input pieces if the PIECE whole is used by arithmetic/float ops."""
        whole = pieceOp.getOut()
        if hasattr(whole, 'isTypeLock') and whole.isTypeLock():
            tp = whole.getType() if hasattr(whole, 'getType') else None
            if tp is not None and hasattr(tp, 'isPrimitiveWhole') and not tp.isPrimitiveWhole():
                return 0
        if vnhi.getSize() != vnlo.getSize():
            return 0
        entryhi = vnhi.getSymbolEntry() if hasattr(vnhi, 'getSymbolEntry') else None
        entrylo = vnlo.getSymbolEntry() if hasattr(vnlo, 'getSymbolEntry') else None
        if entryhi is not None or entrylo is not None:
            if entryhi is None or entrylo is None:
                return 0
            if hasattr(entryhi, 'getSymbol') and hasattr(entrylo, 'getSymbol'):
                if entryhi.getSymbol() is not entrylo.getSymbol():
                    return 0
        isWhole = False
        for desc in whole.getDescend():
            typeop = desc.getOpcode() if hasattr(desc, 'getOpcode') else None
            if typeop is not None:
                if (hasattr(typeop, 'isArithmeticOp') and typeop.isArithmeticOp()) or \
                   (hasattr(typeop, 'isFloatingPointOp') and typeop.isFloatingPointOp()):
                    isWhole = True
                    break
        if not isWhole:
            return 0
        if hasattr(vnhi, 'setPrecisHi'):
            vnhi.setPrecisHi()
        if hasattr(vnlo, 'setPrecisLo'):
            vnlo.setPrecisLo()
        return 1


class RuleDumptyHumpLate(Rule):
    """Late-stage cleanup: backtrack SUBPIECE through PIECE chains.

    C++ ref: ``RuleDumptyHumpLate::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "dumptyhump_late")
    def clone(self, gl):
        return RuleDumptyHumpLate(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        from ghidra.core.opcodes import OpCode as OC
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        pieceOp = vn.getDef()
        if pieceOp.code() != OC.CPUI_PIECE:
            return 0
        out = op.getOut()
        outSize = out.getSize()
        trunc = int(op.getIn(1).getOffset())
        origVn = vn
        while True:
            trialVn = pieceOp.getIn(1)
            trialTrunc = trunc
            if trunc >= trialVn.getSize():
                trialTrunc -= trialVn.getSize()
                trialVn = pieceOp.getIn(0)
            if outSize + trialTrunc > trialVn.getSize():
                break
            vn = trialVn
            trunc = trialTrunc
            if vn.getSize() == outSize:
                break
            if not vn.isWritten():
                break
            pieceOp = vn.getDef()
            if pieceOp.code() != OC.CPUI_PIECE:
                break
        if vn is origVn:
            return 0
        if vn.isWritten() and vn.getDef().code() == OC.CPUI_COPY:
            vn = vn.getDef().getIn(0)
        if outSize != vn.getSize():
            removeOp = op.getIn(0).getDef()
            if op.getIn(1).getOffset() != trunc:
                data.opSetInput(op, data.newConstant(4, trunc), 1)
            data.opSetInput(op, vn, 0)
        elif hasattr(out, 'isAutoLive') and out.isAutoLive():
            removeOp = op.getIn(0).getDef()
            data.opRemoveInput(op, 1)
            data.opSetOpcode(op, OC.CPUI_COPY)
            data.opSetInput(op, vn, 0)
        else:
            removeOp = op
            if hasattr(data, 'totalReplace'):
                data.totalReplace(out, vn)
        if removeOp.getOut() is not None and removeOp.getOut().hasNoDescend():
            if not (hasattr(removeOp.getOut(), 'isAutoLive') and removeOp.getOut().isAutoLive()):
                if hasattr(data, 'opDestroyRecursive'):
                    data.opDestroyRecursive(removeOp, [])
        return 1


class RuleSplitCopy(Rule):
    """Split a COPY of a structured data-type into component copies.

    C++ ref: ``RuleSplitCopy::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "splitcopy")
    def clone(self, gl):
        return RuleSplitCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_COPY]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SplitDatatype
        inType = op.getIn(0).getTypeReadFacing(op) if hasattr(op.getIn(0), 'getTypeReadFacing') else op.getIn(0).getType()
        outType = op.getOut().getTypeDefFacing() if hasattr(op.getOut(), 'getTypeDefFacing') else op.getOut().getType()
        if inType is None or outType is None:
            return 0
        metain = inType.getMetatype() if hasattr(inType, 'getMetatype') else -1
        metaout = outType.getMetatype() if hasattr(outType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if (metain not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT) and
                metaout not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT)):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitCopy(op, inType, outType):
            return 1
        return 0


class RuleSplitLoad(Rule):
    """Split a LOAD of a structured data-type into component loads.

    C++ ref: ``RuleSplitLoad::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "splitload")
    def clone(self, gl):
        return RuleSplitLoad(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_LOAD]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SplitDatatype
        inType = SplitDatatype.getValueDatatype(op, op.getOut().getSize(),
                                                 data.getArch().types if hasattr(data.getArch(), 'types') else None)
        if inType is None:
            return 0
        metain = inType.getMetatype() if hasattr(inType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if metain not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitLoad(op, inType):
            return 1
        return 0


class RuleSplitStore(Rule):
    """Split a STORE of a structured data-type into component stores.

    C++ ref: ``RuleSplitStore::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "splitstore")
    def clone(self, gl):
        return RuleSplitStore(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_STORE]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SplitDatatype
        outType = SplitDatatype.getValueDatatype(op, op.getIn(2).getSize(),
                                                  data.getArch().types if hasattr(data.getArch(), 'types') else None)
        if outType is None:
            return 0
        metain = outType.getMetatype() if hasattr(outType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if metain not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitStore(op, outType):
            return 1
        return 0


class RuleStringCopy(Rule):
    """Replace a sequence of constant-character COPYs with a memcpy/wcsncpy.

    C++ ref: ``RuleStringCopy::applyOp`` in constseq.cc
    """
    def __init__(self, g): super().__init__(g, 0, "stringcopy")
    def clone(self, gl):
        return RuleStringCopy(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_COPY]
    def applyOp(self, op, data):
        if not op.getIn(0).isConstant():
            return 0
        outvn = op.getOut()
        ct = outvn.getType() if hasattr(outvn, 'getType') else None
        if ct is None:
            return 0
        if not (hasattr(ct, 'isCharPrint') and ct.isCharPrint()):
            return 0
        if hasattr(ct, 'isOpaqueString') and ct.isOpaqueString():
            return 0
        if not (hasattr(outvn, 'isAddrTied') and outvn.isAddrTied()):
            return 0
        scope_local = data.getScopeLocal() if hasattr(data, 'getScopeLocal') else None
        if scope_local is None:
            return 0
        entry = scope_local.queryContainer(outvn.getAddr(), outvn.getSize(), op.getAddr())
        if entry is None:
            return 0
        from ghidra.analysis.constseq import StringSequence

        sequence = StringSequence(data, ct, entry, op, outvn.getAddr())
        if not sequence.isValid():
            return 0
        if not sequence.transform():
            return 0
        return 1


class RuleStringStore(Rule):
    """Replace a sequence of constant-character STOREs with a strncpy/wcsncpy.

    C++ ref: ``RuleStringStore::applyOp`` in constseq.cc
    """
    def __init__(self, g): super().__init__(g, 0, "stringstore")
    def clone(self, gl):
        return RuleStringStore(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_STORE]
    def applyOp(self, op, data):
        if not op.getIn(2).isConstant():
            return 0
        ptrvn = op.getIn(1)
        ct = ptrvn.getTypeReadFacing(op) if hasattr(ptrvn, 'getTypeReadFacing') else (ptrvn.getType() if hasattr(ptrvn, 'getType') else None)
        if ct is None:
            return 0
        from ghidra.types.datatype import TYPE_PTR
        if not (hasattr(ct, 'getMetatype') and ct.getMetatype() == TYPE_PTR):
            return 0
        ptrto = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
        if ptrto is None:
            return 0
        if not (hasattr(ptrto, 'isCharPrint') and ptrto.isCharPrint()):
            return 0
        if hasattr(ptrto, 'isOpaqueString') and ptrto.isOpaqueString():
            return 0
        from ghidra.analysis.constseq import HeapSequence

        sequence = HeapSequence(data, ptrto, op)
        if not sequence.isValid():
            return 0
        if not sequence.transform():
            return 0
        return 1


# ---------------------------------------------------------------------------
# Subvar group rules - depend on SubvariableFlow infrastructure
# ---------------------------------------------------------------------------

class RuleSubvarAnd(Rule):
    """Perform sub-variable flow analysis triggered by INT_AND with constant mask.

    C++ ref: ``RuleSubvarAnd::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subvar_and")
    def clone(self, gl):
        return RuleSubvarAnd(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_AND]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        from ghidra.core.address import calc_mask
        if not op.getIn(1).isConstant():
            return 0
        vn = op.getIn(0)
        outvn = op.getOut()
        consume = outvn.getConsume() if hasattr(outvn, 'getConsume') else 0
        if consume != op.getIn(1).getOffset():
            return 0
        if (consume & 1) == 0:
            return 0
        if consume == 1:
            cmask = 1
        else:
            cmask = calc_mask(vn.getSize()) >> 8
            while cmask != 0:
                if cmask == consume:
                    break
                cmask >>= 8
        if cmask == 0:
            return 0
        if op.getOut().hasNoDescend():
            return 0
        subflow = SubvariableFlow(data, vn, cmask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarSubpiece(Rule):
    """Perform sub-variable flow analysis triggered by SUBPIECE.

    C++ ref: ``RuleSubvarSubpiece::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subvar_subpiece")
    def clone(self, gl):
        return RuleSubvarSubpiece(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        from ghidra.core.address import calc_mask
        vn = op.getIn(0)
        outvn = op.getOut()
        flowsize = outvn.getSize()
        sa = int(op.getIn(1).getOffset())
        if flowsize + sa > 8:
            _subvar_debug_log(op, f"skip reason=flowsize_plus_sa flowsize={flowsize} sa={sa}")
            return 0
        mask = calc_mask(flowsize)
        mask <<= (8 * sa)
        aggressive = outvn.isPtrFlow() if hasattr(outvn, 'isPtrFlow') else False
        if not aggressive:
            consume = vn.getConsume() if hasattr(vn, 'getConsume') else 0
            if (consume & mask) != consume:
                _subvar_debug_log(
                    op,
                    f"skip reason=consume_mask consume={consume:#x} mask={mask:#x} "
                    f"vn_flags={(vn._flags if hasattr(vn, '_flags') else 0):#x}",
                )
                return 0
            if op.getOut().hasNoDescend():
                _subvar_debug_log(op, "skip reason=no_descend")
                return 0
        big = False
        if flowsize >= 8 and vn.isInput():
            if hasattr(vn, 'loneDescend') and vn.loneDescend() is op:
                big = True
        subflow = SubvariableFlow(data, vn, mask, aggressive, False, big)
        if not subflow.doTrace():
            _subvar_debug_log(
                op,
                f"skip reason=trace_fail aggressive={int(bool(aggressive))} big={int(bool(big))} "
                f"consume={(vn.getConsume() if hasattr(vn, 'getConsume') else 0):#x} mask={mask:#x}",
            )
            return 0
        _subvar_debug_log(
            op,
            f"fire aggressive={int(bool(aggressive))} big={int(bool(big))} "
            f"consume={(vn.getConsume() if hasattr(vn, 'getConsume') else 0):#x} mask={mask:#x}",
        )
        subflow.doReplacement()
        return 1


class RuleSplitFlow(Rule):
    """Split a variable into logical sub-pieces based on data-flow.

    C++ ref: ``RuleSplitFlow::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "splitflow")
    def clone(self, gl):
        return RuleSplitFlow(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SplitFlow
        lowSize = int(op.getIn(1).getOffset())
        if lowSize == 0:
            return 0
        invn = op.getIn(0)
        if not invn.isWritten():
            return 0
        if (hasattr(invn, "isPrecisLo") and invn.isPrecisLo()) or (hasattr(invn, "isPrecisHi") and invn.isPrecisHi()):
            return 0
        outvn = op.getOut()
        if outvn.getSize() + lowSize != invn.getSize():
            return 0

        concatOp = None
        multiOp = invn.getDef()
        while multiOp.code() == OpCode.CPUI_INDIRECT:
            tmpvn = multiOp.getIn(0)
            if not tmpvn.isWritten():
                return 0
            multiOp = tmpvn.getDef()

        if multiOp.code() == OpCode.CPUI_PIECE:
            if invn.getDef() is not multiOp:
                concatOp = multiOp
        elif multiOp.code() == OpCode.CPUI_MULTIEQUAL:
            for index in range(multiOp.numInput()):
                cur_in = multiOp.getIn(index)
                if not cur_in.isWritten():
                    continue
                tmpOp = cur_in.getDef()
                if tmpOp.code() == OpCode.CPUI_PIECE:
                    concatOp = tmpOp
                    break

        if concatOp is None:
            return 0
        if concatOp.getIn(1).getSize() != lowSize:
            return 0

        splitflow = SplitFlow(data, invn, lowSize)
        if not splitflow.doTrace():
            return 0
        splitflow.apply()
        return 1


class RuleSubvarCompZero(Rule):
    """Perform sub-variable flow analysis triggered by comparison with zero/constant.

    C++ ref: ``RuleSubvarCompZero::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subvar_compzero")
    def clone(self, gl):
        return RuleSubvarCompZero(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_INT_EQUAL]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        from ghidra.core.address import calc_mask
        if not op.getIn(1).isConstant():
            return 0
        vn = op.getIn(0)
        mask = vn.getNZMask() if hasattr(vn, 'getNZMask') else 0
        if mask == 0:
            return 0
        bitnum = -1
        tmp = mask
        pos = 0
        while tmp != 0:
            if tmp & 1:
                if bitnum == -1:
                    bitnum = pos
                else:
                    bitnum = -1
                    break
            pos += 1
            tmp >>= 1
        if bitnum == -1:
            return 0
        if (mask >> bitnum) != 1:
            return 0
        constoff = int(op.getIn(1).getOffset())
        if constoff != mask and constoff != 0:
            return 0
        if op.getOut().hasNoDescend():
            return 0
        if vn.isWritten():
            andop = vn.getDef()
            if andop.numInput() == 0:
                return 0
            vn0 = andop.getIn(0)
            opc = andop.code()
            if opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_RIGHT):
                if vn0.isConstant():
                    return 0
                consume0 = vn0.getConsume() if hasattr(vn0, 'getConsume') else 0
                nzmask0 = vn0.getNZMask() if hasattr(vn0, 'getNZMask') else 0
                mask0 = consume0 & nzmask0
                wholemask = calc_mask(vn0.getSize()) & mask0
                if (wholemask & 0xff) == 0xff:
                    return 0
                if (wholemask & 0xff00) == 0xff00:
                    return 0
        subflow = SubvariableFlow(data, vn, mask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarShift(Rule):
    """Perform sub-variable flow analysis triggered by INT_RIGHT extracting a single bit.

    C++ ref: ``RuleSubvarShift::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subvar_shift")
    def clone(self, gl):
        return RuleSubvarShift(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_RIGHT]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        vn = op.getIn(0)
        if vn.getSize() != 1:
            return 0
        if not op.getIn(1).isConstant():
            return 0
        sa = int(op.getIn(1).getOffset())
        mask = vn.getNZMask() if hasattr(vn, 'getNZMask') else 0
        if (mask >> sa) != 1:
            return 0
        mask = ((mask >> sa) << sa)
        if op.getOut().hasNoDescend():
            return 0
        subflow = SubvariableFlow(data, vn, mask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarZext(Rule):
    """Perform sub-variable flow analysis triggered by INT_ZEXT.

    C++ ref: ``RuleSubvarZext::applyOp`` in subflow.cc
    """
    def __init__(self, g): super().__init__(g, 0, "subvar_zext")
    def clone(self, gl):
        return RuleSubvarZext(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_ZEXT]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        from ghidra.core.address import calc_mask
        vn = op.getOut()
        invn = op.getIn(0)
        mask = calc_mask(invn.getSize())
        subflow = SubvariableFlow(data, vn, mask,
                                   invn.isPtrFlow() if hasattr(invn, 'isPtrFlow') else False,
                                   False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarSext(Rule):
    """Perform sub-variable flow analysis triggered by INT_SEXT.

    C++ ref: ``RuleSubvarSext::applyOp`` in subflow.cc
    """
    _isaggressive: bool = False

    def __init__(self, g): super().__init__(g, 0, "subvar_sext")
    def clone(self, gl):
        return RuleSubvarSext(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_INT_SEXT]
    def applyOp(self, op, data):
        from ghidra.analysis.subflow import SubvariableFlow
        from ghidra.core.address import calc_mask
        vn = op.getOut()
        invn = op.getIn(0)
        mask = calc_mask(invn.getSize())
        subflow = SubvariableFlow(data, vn, mask, self._isaggressive, True, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1
    def reset(self, data):
        self._isaggressive = False
