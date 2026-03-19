"""Tests for ghidra.transform.action -- Action, Rule, ActionGroup, ActionPool, ActionDatabase."""
from __future__ import annotations

import io
from ghidra.transform.action import (
    Action, ActionGroupList, ActionGroup, ActionPool,
    ActionDatabase, Rule, next_specifyterm,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ConcreteAction(Action):
    """Minimal concrete Action for testing."""
    def __init__(self, nm="test", g="testgroup", flags=0):
        super().__init__(flags, nm, g)
        self._applied = False

    def clone(self, gl):
        if gl.contains(self._basegroup):
            return _ConcreteAction(self._name, self._basegroup, self._flags)
        return None

    def apply(self, data):
        if not self._applied:
            self._applied = True
            self._count += 1
        return 0


class _FakeData:
    """Minimal Funcdata stub for Action.perform()."""
    def getArch(self):
        return _FakeArch()

class _FakeArch:
    def printMessage(self, msg):
        pass


# ---------------------------------------------------------------------------
# next_specifyterm
# ---------------------------------------------------------------------------

class TestNextSpecifyterm:
    def test_single(self):
        tok, rem = next_specifyterm("hello")
        assert tok == "hello"
        assert rem == ""

    def test_colon_sep(self):
        tok, rem = next_specifyterm("foo:bar:baz")
        assert tok == "foo"
        assert rem == "bar:baz"

    def test_empty(self):
        tok, rem = next_specifyterm("")
        assert tok == ""
        assert rem == ""


# ---------------------------------------------------------------------------
# ActionGroupList
# ---------------------------------------------------------------------------

class TestActionGroupList:
    def test_empty(self):
        gl = ActionGroupList()
        assert gl.contains("x") is False

    def test_contains(self):
        gl = ActionGroupList()
        gl.list.add("grp1")
        assert gl.contains("grp1") is True
        assert gl.contains("grp2") is False


# ---------------------------------------------------------------------------
# Action basics
# ---------------------------------------------------------------------------

class TestAction:
    def test_name_group(self):
        a = _ConcreteAction("myact", "mygrp")
        assert a.getName() == "myact"
        assert a.getGroup() == "mygrp"

    def test_initial_status(self):
        a = _ConcreteAction()
        assert a.getStatus() == Action.status_start

    def test_initial_stats(self):
        a = _ConcreteAction()
        assert a.getNumTests() == 0
        assert a.getNumApply() == 0

    def test_perform(self):
        a = _ConcreteAction()
        fd = _FakeData()
        result = a.perform(fd)
        assert result >= 0
        assert a.getNumTests() == 1

    def test_reset(self):
        a = _ConcreteAction()
        fd = _FakeData()
        a.perform(fd)
        a.reset(fd)
        assert a.getStatus() == Action.status_start

    def test_reset_stats(self):
        a = _ConcreteAction()
        fd = _FakeData()
        a.perform(fd)
        a.resetStats()
        assert a.getNumTests() == 0
        assert a.getNumApply() == 0

    def test_debug_toggle(self):
        a = _ConcreteAction("dbg")
        assert a.turnOnDebug("dbg") is True
        assert a.turnOnDebug("other") is False
        assert a.turnOffDebug("dbg") is True
        assert a.turnOffDebug("other") is False

    def test_warnings_toggle(self):
        a = _ConcreteAction()
        a.turnOnWarnings()
        assert (a._flags & Action.rule_warnings_on) != 0
        a.turnOffWarnings()
        assert (a._flags & Action.rule_warnings_on) == 0

    def test_clear_breakpoints(self):
        a = _ConcreteAction()
        a._breakpoint = Action.break_start | Action.break_action
        a.clearBreakPoints()
        assert a._breakpoint == 0

    def test_print_statistics(self):
        a = _ConcreteAction("stat_act")
        buf = io.StringIO()
        a.printStatistics(buf)
        assert "stat_act" in buf.getvalue()
        assert "Tested=0" in buf.getvalue()

    def test_print(self):
        a = _ConcreteAction("print_act")
        buf = io.StringIO()
        a.print(buf, 0, 0)
        assert "print_act" in buf.getvalue()

    def test_print_state(self):
        a = _ConcreteAction("state_act")
        buf = io.StringIO()
        a.printState(buf)
        assert "state_act" in buf.getvalue()

    def test_clone(self):
        a = _ConcreteAction("orig", "grp")
        gl = ActionGroupList()
        gl.list.add("grp")
        clone = a.clone(gl)
        assert clone is not None
        assert clone.getName() == "orig"

    def test_clone_not_in_group(self):
        a = _ConcreteAction("orig", "grp")
        gl = ActionGroupList()
        assert a.clone(gl) is None

    def test_flag_constants(self):
        assert Action.rule_repeatapply == 4
        assert Action.rule_onceperfunc == 8
        assert Action.rule_oneactperfunc == 16
        assert Action.rule_debug == 32

    def test_status_constants(self):
        assert Action.status_start == 1
        assert Action.status_breakstarthit == 2
        assert Action.status_repeat == 4
        assert Action.status_mid == 8
        assert Action.status_end == 16
        assert Action.status_actionbreak == 32

    def test_break_constants(self):
        assert Action.break_start == 1
        assert Action.tmpbreak_start == 2
        assert Action.break_action == 4
        assert Action.tmpbreak_action == 8


# ---------------------------------------------------------------------------
# ActionGroup
# ---------------------------------------------------------------------------

class TestActionGroup:
    def test_empty(self):
        ag = ActionGroup(0, "grp1")
        assert ag.getName() == "grp1"
        assert len(ag._list) == 0

    def test_add_action(self):
        ag = ActionGroup(0, "grp1")
        a = _ConcreteAction("child", "grp1")
        ag.addAction(a)
        assert len(ag._list) == 1

    def test_perform(self):
        ag = ActionGroup(0, "grp1")
        a = _ConcreteAction("child", "grp1")
        ag.addAction(a)
        fd = _FakeData()
        result = ag.perform(fd)
        assert result >= 0

    def test_reset(self):
        ag = ActionGroup(0, "grp1")
        a = _ConcreteAction("child", "grp1")
        ag.addAction(a)
        fd = _FakeData()
        ag.perform(fd)
        ag.reset(fd)
        assert ag.getStatus() == Action.status_start

    def test_clone(self):
        ag = ActionGroup(0, "grp1")
        a = _ConcreteAction("child", "grp1")
        ag.addAction(a)
        gl = ActionGroupList()
        gl.list.add("grp1")
        clone = ag.clone(gl)
        assert clone is not None
        assert len(clone._list) == 1

    def test_print(self):
        ag = ActionGroup(0, "grp1")
        a = _ConcreteAction("child", "grp1")
        ag.addAction(a)
        buf = io.StringIO()
        ag.print(buf, 0, 0)
        assert "grp1" in buf.getvalue()


# ---------------------------------------------------------------------------
# ActionPool
# ---------------------------------------------------------------------------

class TestActionPool:
    def test_empty(self):
        ap = ActionPool(0, "pool1")
        assert ap.getName() == "pool1"

    def test_add_rule(self):
        ap = ActionPool(0, "pool1")

        class _FakeRule(Rule):
            def __init__(self):
                super().__init__("pool1", 0, "testrule")
            def clone(self, gl):
                return _FakeRule() if gl.contains("pool1") else None
            def getOpList(self):
                return []
            def applyOp(self, op, data):
                return 0

        r = _FakeRule()
        ap.addRule(r)
        assert len(ap._allrules) == 1

    def test_clone_with_rules(self):
        ap = ActionPool(0, "pool1")

        class _FakeRule2(Rule):
            def __init__(self):
                super().__init__("pool1", 0, "testrule2")
            def clone(self, gl):
                return _FakeRule2() if gl.contains("pool1") else None
            def getOpList(self):
                return []

        ap.addRule(_FakeRule2())
        gl = ActionGroupList()
        gl.list.add("pool1")
        clone = ap.clone(gl)
        assert clone is not None
        assert len(clone._allrules) == 1

    def test_clone_empty(self):
        ap = ActionPool(0, "pool1")
        gl = ActionGroupList()
        gl.list.add("pool1")
        clone = ap.clone(gl)
        assert clone is None


# ---------------------------------------------------------------------------
# ActionDatabase
# ---------------------------------------------------------------------------

class TestActionDatabase:
    def test_empty(self):
        adb = ActionDatabase()
        assert adb.getCurrent() is None
        assert adb.getCurrentName() == ""

    def test_register_and_get_action(self):
        adb = ActionDatabase()
        ag = ActionGroup(0, "testgrp")
        adb.registerAction("myaction", ag)
        got = adb.getAction("myaction")
        assert got is ag

    def test_add_to_group(self):
        adb = ActionDatabase()
        assert adb.addToGroup("decompile", "base") is True
        assert adb.addToGroup("decompile", "base") is False

    def test_remove_from_group(self):
        adb = ActionDatabase()
        adb.addToGroup("decompile", "base")
        assert adb.removeFromGroup("decompile", "base") is True
        assert adb.removeFromGroup("decompile", "base") is False

    def test_set_group(self):
        adb = ActionDatabase()
        adb.setGroup("mygrp", ["a", "b", "c"])
        gl = adb.getGroup("mygrp")
        assert gl.contains("a")
        assert gl.contains("b")
        assert gl.contains("c")
        assert not gl.contains("d")

    def test_clone_group(self):
        adb = ActionDatabase()
        adb.setGroup("orig", ["a", "b"])
        adb.cloneGroup("orig", "copy")
        gl = adb.getGroup("copy")
        assert gl.contains("a")
        assert gl.contains("b")

    def test_repr(self):
        adb = ActionDatabase()
        r = repr(adb)
        assert "ActionDatabase" in r
