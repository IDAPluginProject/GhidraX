"""Tests for ghidra.transform.deadcode -- ActionDeadCode static helpers."""
from __future__ import annotations

from ghidra.transform.deadcode import ActionDeadCode
from ghidra.core.address import calc_mask


# ---------------------------------------------------------------------------
# Mock classes
# ---------------------------------------------------------------------------

class _MockVarnode:
    def __init__(self, size, consume=0):
        self._size = size
        self._consume = consume
        self._flags = 0
        self._written = False
        self._def = None

    def getSize(self):
        return self._size

    def getConsume(self):
        return self._consume

    def setConsume(self, val):
        self._consume = val

    def isConsumeVacuous(self):
        return (self._flags & 1) != 0

    def setConsumeVacuous(self):
        self._flags |= 1

    def isConsumeList(self):
        return (self._flags & 2) != 0

    def setConsumeList(self):
        self._flags |= 2

    def clearConsumeList(self):
        self._flags &= ~2

    def isWritten(self):
        return self._written

    def getDef(self):
        return self._def


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestActionDeadCode:
    def test_construction(self):
        adc = ActionDeadCode("deadgrp")
        assert adc.getName() == "deadcode"
        assert adc.getGroup() == "deadgrp"

    def test_clone(self):
        from ghidra.transform.action import ActionGroupList
        adc = ActionDeadCode("deadgrp")
        gl = ActionGroupList()
        gl.list.add("deadgrp")
        clone = adc.clone(gl)
        assert clone is not None
        assert clone.getName() == "deadcode"

    def test_clone_not_in_group(self):
        from ghidra.transform.action import ActionGroupList
        adc = ActionDeadCode("deadgrp")
        gl = ActionGroupList()
        assert adc.clone(gl) is None

    def test_push_consumed_basic(self):
        vn = _MockVarnode(4, consume=0)
        worklist = []
        ActionDeadCode._pushConsumed(0xFF, vn, worklist)
        assert vn.getConsume() == 0xFF
        assert vn.isConsumeVacuous()

    def test_push_consumed_no_change(self):
        vn = _MockVarnode(4, consume=0xFF)
        vn.setConsumeVacuous()
        worklist = []
        ActionDeadCode._pushConsumed(0xFF, vn, worklist)
        # No new items added since consume didn't change
        assert len(worklist) == 0

    def test_push_consumed_adds_to_worklist(self):
        vn = _MockVarnode(4, consume=0)
        vn._written = True
        worklist = []
        ActionDeadCode._pushConsumed(0xFF, vn, worklist)
        assert len(worklist) == 1
        assert worklist[0] is vn

    def test_push_consumed_masks_by_size(self):
        vn = _MockVarnode(1, consume=0)
        worklist = []
        ActionDeadCode._pushConsumed(0xFFFF, vn, worklist)
        # Should be masked to 1-byte size
        assert vn.getConsume() == 0xFF
