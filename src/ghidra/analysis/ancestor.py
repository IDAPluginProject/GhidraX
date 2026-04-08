"""TraverseNode and AncestorRealistic — advanced parameter trial analysis.

C++ refs:
  - ``expression.hh`` / ``TraverseNode``
  - ``funcdata.hh`` / ``AncestorRealistic``
  - ``funcdata_varnode.cc`` / ``AncestorRealistic::enterNode``, ``uponPop``, ``execute``
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional

from ghidra.core.space import IPTR_INTERNAL, IPTR_SPACEBASE
from ghidra.ir.op import OpCode

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.fspec.fspec import ParamTrial


# ---------------------------------------------------------------------------
# TraverseNode
# ---------------------------------------------------------------------------

class TraverseNode:
    """Node for a forward traversal of a Varnode expression.

    C++ ref: ``expression.hh::TraverseNode``
    """
    actionalt = 1
    indirect = 2
    indirectalt = 4
    lsb_truncated = 8
    concat_high = 0x10

    __slots__ = ('vn', 'flags')

    def __init__(self, vn: 'Varnode', flags: int = 0):
        self.vn = vn
        self.flags = flags

    @staticmethod
    def isAlternatePathValid(vn: 'Varnode', flags: int) -> bool:
        """Return True if the alternate path looks more valid than the main path.

        C++ ref: ``expression.cc::TraverseNode::isAlternatePathValid``.
        """
        if (flags & (TraverseNode.indirect | TraverseNode.indirectalt)) == TraverseNode.indirect:
            return True
        if (flags & (TraverseNode.indirect | TraverseNode.indirectalt)) == TraverseNode.indirectalt:
            return False
        if (flags & TraverseNode.actionalt) != 0:
            return True
        if vn.loneDescend() is None:
            return False
        op = vn.getDef()
        if op is None:
            return True
        while (hasattr(op, 'isIncidentalCopy') and op.isIncidentalCopy()
               and op.code() == OpCode.CPUI_COPY):
            vn = op.getIn(0)
            if vn.loneDescend() is None:
                return False
            op = vn.getDef()
            if op is None:
                return True
        return not op.isMarker()


# ---------------------------------------------------------------------------
# AncestorRealistic
# ---------------------------------------------------------------------------

class _State:
    """Node in a depth-first traversal of ancestors."""
    seen_solid0 = 1
    seen_solid1 = 2
    seen_kill = 4

    __slots__ = ('op', 'slot', 'flags', 'offset')

    def __init__(self, op: 'PcodeOp', slot_or_old=0):
        self.op = op
        if isinstance(slot_or_old, _State):
            old: _State = slot_or_old
            self.slot = 0
            self.flags = 0
            self.offset = old.offset + int(op.getIn(1).getOffset())
        else:
            self.slot = int(slot_or_old)
            self.flags = 0
            self.offset = 0

    def getSolidSlot(self) -> int:
        return 0 if (self.flags & _State.seen_solid0) != 0 else 1

    def markSolid(self, s: int) -> None:
        self.flags |= (_State.seen_solid0 if s == 0 else _State.seen_solid1)

    def markKill(self) -> None:
        self.flags |= _State.seen_kill

    def seenSolid(self) -> bool:
        return (self.flags & (_State.seen_solid0 | _State.seen_solid1)) != 0

    def seenKill(self) -> bool:
        return (self.flags & _State.seen_kill) != 0


class AncestorRealistic:
    """Determine if a parameter trial has realistic ancestors.

    Performs a depth-first traversal backward through the data-flow to check
    whether the Varnode makes sense as parameter passing / return value storage.

    C++ ref: ``funcdata.hh / funcdata_varnode.cc``
    """
    # Traversal commands
    enter_node = 0
    pop_success = 1
    pop_solid = 2
    pop_fail = 3
    pop_failkill = 4

    def __init__(self):
        self.trial: Optional['ParamTrial'] = None
        self.stateStack: List[_State] = []
        self.markedVn: List['Varnode'] = []
        self.multiDepth: int = 0
        self.allowFailingPath: bool = False

    def mark(self, vn: 'Varnode') -> None:
        self.markedVn.append(vn)
        vn.setMark()

    # -----------------------------------------------------------------
    def checkConditionalExe(self, state: _State) -> bool:
        bl = state.op.getParent()
        if bl.sizeIn() != 2:
            return False
        solidBlock = bl.getIn(state.getSolidSlot())
        if solidBlock.sizeOut() != 1:
            return False
        return True

    # -----------------------------------------------------------------
    def enterNode(self) -> int:
        state = self.stateStack[-1]
        stateVn: 'Varnode' = state.op.getIn(state.slot)
        if stateVn.isMark():
            return self.pop_success
        if not stateVn.isWritten():
            if stateVn.isInput():
                if stateVn.isUnaffected():
                    return self.pop_fail
                if stateVn.isPersist():
                    return self.pop_success
                if not stateVn.isDirectWrite():
                    return self.pop_fail
            return self.pop_success

        self.mark(stateVn)
        op = stateVn.getDef()
        opc = op.code()

        if opc == OpCode.CPUI_INDIRECT:
            if op.isIndirectCreation():
                self.trial.setIndCreateFormed()
                if op.getIn(0).isIndirectZero():
                    return self.pop_failkill
                return self.pop_success
            if not op.isIndirectStore():
                if op.getOut().isReturnAddress():
                    return self.pop_fail
                if self.trial.isKilledByCall():
                    return self.pop_fail
            self.stateStack.append(_State(op, 0))
            return self.enter_node

        elif opc == OpCode.CPUI_SUBPIECE:
            isInternal = op.getOut().getSpace().getType() == IPTR_INTERNAL
            isIncidental = op.isIncidentalCopy() or op.getIn(0).isIncidentalCopy()
            matchOffset = op.getOut().overlap(op.getIn(0)) == int(op.getIn(1).getOffset())
            if isInternal or isIncidental or matchOffset:
                self.stateStack.append(_State(op, state))
                return self.enter_node
            # Minimal traversal for other SUBPIECEs
            while True:
                vn = op.getIn(0)
                if (not vn.isMark()) and vn.isInput():
                    if vn.isUnaffected() or (not vn.isDirectWrite()):
                        return self.pop_fail
                op = vn.getDef()
                if op is None:
                    break
                c = op.code()
                if c != OpCode.CPUI_COPY and c != OpCode.CPUI_SUBPIECE:
                    break
            return self.pop_solid

        elif opc == OpCode.CPUI_COPY:
            isInternal = op.getOut().getSpace().getType() == IPTR_INTERNAL
            isIncidental = op.isIncidentalCopy() or op.getIn(0).isIncidentalCopy()
            sameAddr = op.getOut().getAddr() == op.getIn(0).getAddr()
            if isInternal or isIncidental or sameAddr:
                self.stateStack.append(_State(op, 0))
                return self.enter_node
            # Minimal traversal for other COPYs
            vn = op.getIn(0)
            while True:
                if (not vn.isMark()) and vn.isInput():
                    if not vn.isDirectWrite():
                        return self.pop_fail
                if op.isStoreUnmapped():
                    return self.pop_fail
                op = vn.getDef()
                if op is None:
                    break
                c = op.code()
                if c == OpCode.CPUI_COPY or c == OpCode.CPUI_SUBPIECE:
                    vn = op.getIn(0)
                elif c == OpCode.CPUI_PIECE:
                    vn = op.getIn(1)
                else:
                    break
            return self.pop_solid

        elif opc == OpCode.CPUI_MULTIEQUAL:
            self.multiDepth += 1
            self.stateStack.append(_State(op, 0))
            return self.enter_node

        elif opc == OpCode.CPUI_PIECE:
            if stateVn.getSize() > self.trial.getSize():
                if state.offset == 0 and op.getIn(1).getSize() <= self.trial.getSize():
                    self.stateStack.append(_State(op, 1))
                    return self.enter_node
                elif state.offset == op.getIn(1).getSize() and op.getIn(0).getSize() <= self.trial.getSize():
                    self.stateStack.append(_State(op, 0))
                    return self.enter_node
                if stateVn.getSpace().getType() != IPTR_SPACEBASE:
                    return self.pop_fail
            return self.pop_solid

        else:
            return self.pop_solid

    # -----------------------------------------------------------------
    def uponPop(self, pop_command: int) -> int:
        state = self.stateStack[-1]
        if state.op.code() == OpCode.CPUI_MULTIEQUAL:
            prevstate = self.stateStack[-2]
            if pop_command == self.pop_fail:
                self.multiDepth -= 1
                self.stateStack.pop()
                return pop_command
            elif pop_command == self.pop_solid and self.multiDepth == 1 and state.op.numInput() == 2:
                prevstate.markSolid(state.slot)
            elif pop_command == self.pop_failkill:
                prevstate.markKill()
            state.slot += 1
            if state.slot == state.op.numInput():
                if prevstate.seenSolid():
                    pop_command = self.pop_success
                    if prevstate.seenKill():
                        if self.allowFailingPath:
                            if not self.checkConditionalExe(state):
                                pop_command = self.pop_fail
                            else:
                                self.trial.setCondExeEffect()
                        else:
                            pop_command = self.pop_fail
                elif prevstate.seenKill():
                    pop_command = self.pop_failkill
                else:
                    pop_command = self.pop_success
                self.multiDepth -= 1
                self.stateStack.pop()
                return pop_command
            return self.enter_node
        else:
            self.stateStack.pop()
            return pop_command

    # -----------------------------------------------------------------
    def execute(self, op: 'PcodeOp', slot: int, t: 'ParamTrial', allowFail: bool) -> bool:
        """Perform a full ancestor check on a given parameter trial.

        C++ ref: ``AncestorRealistic::execute``
        """
        self.trial = t
        self.allowFailingPath = allowFail
        self.markedVn.clear()
        self.stateStack.clear()
        self.multiDepth = 0

        inVn = op.getIn(slot)
        if inVn.isInput():
            if not t.hasCondExeEffect():
                return False

        command = self.enter_node
        self.stateStack.append(_State(op, slot))
        while self.stateStack:
            if command == self.enter_node:
                command = self.enterNode()
            else:
                command = self.uponPop(command)

        # Clean up marks
        for vn in self.markedVn:
            vn.clearMark()

        if command == self.pop_success:
            t.setAncestorRealistic()
            return True
        elif command == self.pop_solid:
            t.setAncestorRealistic()
            t.setAncestorSolid()
            return True
        return False
