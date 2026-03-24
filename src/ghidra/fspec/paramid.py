"""
ParamMeasure / ParamIDAnalysis: Parameter identification and ranking.
Corresponds to paramid.hh / paramid.cc.

Classes:
- **ParamMeasure** — Measures the quality/rank of a parameter or return value
  by walking forward (for inputs) or backward (for outputs) through the data-flow graph.
- **ParamIDAnalysis** — Collects ParamMeasure objects for all inputs and outputs of a function.
"""
from __future__ import annotations

from enum import IntEnum
from typing import List, Optional, TYPE_CHECKING

from ghidra.core.marshal import (
    ATTRIB_MODEL, ATTRIB_NAME, ATTRIB_VAL, ATTRIB_EXTRAPOP,
    ELEM_ADDR, ELEM_INPUT, ELEM_OUTPUT,
    ELEM_PARAMMEASURES, ELEM_PROTO, ELEM_RANK,
)
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.core.address import Address
    from ghidra.core.types import Datatype
    from ghidra.core.marshal import Encoder


MAXDEPTH = 10


class ParamIDIO(IntEnum):
    INPUT = 0
    OUTPUT = 1


class ParamRank(IntEnum):
    BESTRANK = 1
    DIRECTWRITEWITHOUTREAD = 1
    DIRECTREAD = 2
    DIRECTWRITEWITHREAD = 2
    DIRECTWRITEUNKNOWNREAD = 3
    SUBFNPARAM = 4
    THISFNPARAM = 4
    SUBFNRETURN = 5
    THISFNRETURN = 5
    INDIRECT = 6
    WORSTRANK = 7


class _WalkState:
    __slots__ = ('best', 'depth', 'terminalrank')

    def __init__(self, best: bool, terminalrank: int) -> None:
        self.best: bool = best
        self.depth: int = 0
        self.terminalrank: int = terminalrank


class ParamMeasure:
    """Measures the quality/rank of a potential parameter or return value."""

    def __init__(self, addr: Address, sz: int, dt: Optional[Datatype],
                 io_in: int) -> None:
        self.vndata = VarnodeData()
        self.vndata.space = addr.getSpace()
        self.vndata.offset = addr.getOffset()
        self.vndata.size = sz
        self.vntype: Optional[Datatype] = dt
        self.io: int = io_in
        self.rank: int = ParamRank.WORSTRANK
        self.numcalls: int = 0

    def _updaterank(self, rank_in: int, best: bool) -> None:
        if best:
            self.rank = min(self.rank, rank_in)
        else:
            self.rank = max(self.rank, rank_in)

    def _walkforward(self, state: _WalkState, ignoreop: Optional[PcodeOp],
                     vn: Varnode) -> None:
        state.depth += 1
        if state.depth >= MAXDEPTH:
            state.depth -= 1
            return

        for op in vn.getDescend():
            if self.rank == state.terminalrank:
                break
            if op is ignoreop:
                continue
            oc = op.code()
            if oc in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND):
                if op.getSlot(vn) == 0:
                    self._updaterank(ParamRank.DIRECTREAD, state.best)
            elif oc == OpCode.CPUI_CBRANCH:
                if op.getSlot(vn) < 2:
                    self._updaterank(ParamRank.DIRECTREAD, state.best)
            elif oc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                if op.getSlot(vn) == 0:
                    self._updaterank(ParamRank.DIRECTREAD, state.best)
                else:
                    self.numcalls += 1
                    self._updaterank(ParamRank.SUBFNPARAM, state.best)
            elif oc == OpCode.CPUI_CALLOTHER:
                self._updaterank(ParamRank.DIRECTREAD, state.best)
            elif oc == OpCode.CPUI_RETURN:
                self._updaterank(ParamRank.THISFNRETURN, state.best)
            elif oc == OpCode.CPUI_INDIRECT:
                self._updaterank(ParamRank.INDIRECT, state.best)
            elif oc == OpCode.CPUI_MULTIEQUAL:
                slot = op.getSlot(vn)
                if not op.getParent().isLoopIn(slot):
                    self._walkforward(state, None, op.getOut())
            else:
                self._updaterank(ParamRank.DIRECTREAD, state.best)

        state.depth -= 1

    def _walkbackward(self, state: _WalkState, ignoreop: Optional[PcodeOp],
                      vn: Varnode) -> None:
        if hasattr(vn, 'isInput') and vn.isInput():
            self._updaterank(ParamRank.THISFNPARAM, state.best)
            return
        if not vn.isWritten():
            self._updaterank(ParamRank.THISFNPARAM, state.best)
            return

        op = vn.getDef()
        oc = op.code()

        if oc in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND,
                  OpCode.CPUI_CBRANCH, OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            pass
        elif oc == OpCode.CPUI_CALLOTHER:
            if op.getOut() is not None:
                self._updaterank(ParamRank.DIRECTREAD, state.best)
        elif oc == OpCode.CPUI_RETURN:
            self._updaterank(ParamRank.SUBFNRETURN, state.best)
        elif oc == OpCode.CPUI_INDIRECT:
            self._updaterank(ParamRank.INDIRECT, state.best)
        elif oc == OpCode.CPUI_MULTIEQUAL:
            for slot in range(op.numInput()):
                if self.rank == state.terminalrank:
                    break
                if not op.getParent().isLoopIn(slot):
                    self._walkbackward(state, op, op.getIn(slot))
        else:
            pmfw = ParamMeasure(vn.getAddr(), vn.getSize(),
                                vn.getType() if hasattr(vn, 'getType') else None,
                                ParamIDIO.INPUT)
            pmfw.calculateRank(False, vn, ignoreop)
            if pmfw.getMeasure() == ParamRank.DIRECTREAD:
                self._updaterank(ParamRank.DIRECTWRITEWITHREAD, state.best)
            else:
                self._updaterank(ParamRank.DIRECTWRITEWITHOUTREAD, state.best)

    def calculateRank(self, best: bool, basevn: Varnode,
                      ignoreop: Optional[PcodeOp]) -> None:
        """Calculate the rank of this parameter measure."""
        if best:
            self.rank = ParamRank.WORSTRANK
            terminal = (ParamRank.DIRECTREAD if self.io == ParamIDIO.INPUT
                        else ParamRank.DIRECTWRITEWITHOUTREAD)
        else:
            self.rank = ParamRank.BESTRANK
            terminal = ParamRank.INDIRECT

        state = _WalkState(best, terminal)
        self.numcalls = 0

        if self.io == ParamIDIO.INPUT:
            self._walkforward(state, ignoreop, basevn)
        else:
            self._walkbackward(state, ignoreop, basevn)

    def encode(self, encoder: Encoder, tag, moredetail: bool) -> None:
        """Encode this parameter measure to an encoder."""
        encoder.openElement(tag)
        encoder.openElement(ELEM_ADDR)
        self.vndata.space.encodeAttributes(encoder, self.vndata.offset, self.vndata.size)
        encoder.closeElement(ELEM_ADDR)
        if self.vntype is not None:
            self.vntype.encodeRef(encoder)
        if moredetail:
            encoder.openElement(ELEM_RANK)
            encoder.writeSignedInteger(ATTRIB_VAL, self.rank)
            encoder.closeElement(ELEM_RANK)
        encoder.closeElement(tag)

    def savePretty(self, moredetail: bool = False) -> str:
        """Return a pretty-printed string representation."""
        lines = []
        lines.append(f"  Space: {self.vndata.space.getName()}")
        lines.append(f"  Addr: {self.vndata.offset}")
        lines.append(f"  Size: {self.vndata.size}")
        lines.append(f"  Rank: {self.rank}")
        return "\n".join(lines) + "\n"

    def getMeasure(self) -> int:
        """Return the current rank value."""
        return self.rank


class ParamIDAnalysis:
    """Collect and rank all parameter measures for a function."""

    def __init__(self, fd: Funcdata, justproto: bool = False) -> None:
        self.fd: Funcdata = fd
        self.InputParamMeasures: List[ParamMeasure] = []
        self.OutputParamMeasures: List[ParamMeasure] = []

        if justproto:
            fproto = fd.getFuncProto()
            num = fproto.numParams()
            for i in range(num):
                param = fproto.getParam(i)
                pm = ParamMeasure(param.getAddress(), param.getSize(),
                                  param.getType(), ParamIDIO.INPUT)
                self.InputParamMeasures.append(pm)
                vn = fd.findVarnodeInput(param.getSize(), param.getAddress())
                if vn is not None:
                    pm.calculateRank(True, vn, None)

            outparam = fproto.getOutput()
            if outparam is not None and not outparam.getAddress().isInvalid():
                opm = ParamMeasure(outparam.getAddress(), outparam.getSize(),
                                   outparam.getType(), ParamIDIO.OUTPUT)
                self.OutputParamMeasures.append(opm)
                for rtn_op in fd.iterOp(OpCode.CPUI_RETURN):
                    if rtn_op.numInput() == 2:
                        ovn = rtn_op.getIn(1)
                        if ovn is not None:
                            opm.calculateRank(True, ovn, rtn_op)
                            break
        else:
            for invn in fd.iterInputVarnodes():
                pm = ParamMeasure(invn.getAddr(), invn.getSize(),
                                  invn.getType() if hasattr(invn, 'getType') else None,
                                  ParamIDIO.INPUT)
                self.InputParamMeasures.append(pm)
                pm.calculateRank(True, invn, None)

    def encode(self, encoder: Encoder, moredetail: bool) -> None:
        """Encode the full parameter analysis to an encoder."""
        encoder.openElement(ELEM_PARAMMEASURES)
        encoder.writeString(ATTRIB_NAME, self.fd.getName())
        self.fd.getAddress().encode(encoder)
        encoder.openElement(ELEM_PROTO)

        fproto = self.fd.getFuncProto()
        encoder.writeString(ATTRIB_MODEL, fproto.getModelName())
        extrapop = fproto.getExtraPop()
        if extrapop == -1:
            encoder.writeString(ATTRIB_EXTRAPOP, "unknown")
        else:
            encoder.writeSignedInteger(ATTRIB_EXTRAPOP, extrapop)
        encoder.closeElement(ELEM_PROTO)

        for pm in self.InputParamMeasures:
            pm.encode(encoder, ELEM_INPUT, moredetail)
        for pm in self.OutputParamMeasures:
            pm.encode(encoder, ELEM_OUTPUT, moredetail)

        encoder.closeElement(ELEM_PARAMMEASURES)

    def savePretty(self, moredetail: bool = False) -> str:
        """Return a pretty-printed string representation."""
        lines = []
        lines.append(f"Param Measures")
        lines.append(f"Function: {self.fd.getName()}")
        lines.append(f"Address: 0x{self.fd.getAddress().getOffset():x}")

        fproto = self.fd.getFuncProto()
        lines.append(f"Model: {fproto.getModelName()}")
        lines.append(f"Extrapop: {fproto.getExtraPop()}")
        lines.append(f"Num Params: {len(self.InputParamMeasures)}")
        for pm in self.InputParamMeasures:
            lines.append(pm.savePretty(moredetail))
        lines.append(f"Num Returns: {len(self.OutputParamMeasures)}")
        for pm in self.OutputParamMeasures:
            lines.append(pm.savePretty(moredetail))
        lines.append("")
        return "\n".join(lines)
