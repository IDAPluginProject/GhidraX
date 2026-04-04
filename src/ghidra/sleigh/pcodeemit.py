"""
P-code emitter for instantiating translated ops directly into Funcdata.

Corresponds to the native ``PcodeEmitFd`` helper in ``funcdata.hh`` /
``funcdata.cc``.
"""

from __future__ import annotations

from typing import List, Optional

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.translate import PcodeEmit


class PcodeEmitFd(PcodeEmit):
    """Materialize translated p-code into a Funcdata dead-list."""

    def __init__(self) -> None:
        self._fd = None

    def setFuncdata(self, fd) -> None:
        self._fd = fd

    def dump(
        self,
        addr: Address,
        opc: OpCode,
        outvar: Optional[VarnodeData],
        vars_: List[VarnodeData],
        isize: int,
    ) -> None:
        fd = self._fd
        if fd is None:
            raise RuntimeError("PcodeEmitFd has no Funcdata attached")

        if outvar is not None:
            op = fd.newOp(isize, addr)
            fd.newVarnodeOut(outvar.size, Address(outvar.space, outvar.offset), op)
        else:
            op = fd.newOp(isize, addr)

        fd.opSetOpcode(op, opc)

        start_slot = 0
        if op.isCodeRef() and vars_:
            addrcode = Address(vars_[0].space, vars_[0].offset)
            fd.opSetInput(op, fd.newCodeRef(addrcode), 0)
            start_slot = 1

        for slot in range(start_slot, isize):
            var = vars_[slot]
            vn = fd.newVarnode(var.size, Address(var.space, var.offset))
            if opc in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE) and slot == 0 and hasattr(vn, "setSpaceFromConst"):
                arch = fd.getArch() if hasattr(fd, "getArch") else None
                data_space = arch.getDefaultDataSpace() if arch is not None and hasattr(arch, "getDefaultDataSpace") else None
                if data_space is not None:
                    vn.setSpaceFromConst(data_space)
            fd.opSetInput(op, vn, slot)
